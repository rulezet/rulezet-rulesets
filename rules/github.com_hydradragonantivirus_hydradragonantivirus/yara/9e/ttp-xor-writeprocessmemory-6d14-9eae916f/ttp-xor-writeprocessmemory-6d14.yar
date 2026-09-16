rule TTP_XOR_WriteProcessMemory_6d14 {
  strings:
    $key_6d14 = { 3a 66 [2] 08 44 [2] 0e 71 [2] 20 71 [2] 1f 6d }

  condition:
    any of them
}