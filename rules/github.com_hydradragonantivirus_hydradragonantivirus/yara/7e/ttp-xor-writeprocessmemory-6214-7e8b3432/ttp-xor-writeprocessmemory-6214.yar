rule TTP_XOR_WriteProcessMemory_6214 {
  strings:
    $key_6214 = { 35 66 [2] 07 44 [2] 01 71 [2] 2f 71 [2] 10 6d }

  condition:
    any of them
}