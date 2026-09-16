rule TTP_XOR_WriteProcessMemory_5b14 {
  strings:
    $key_5b14 = { 0c 66 [2] 3e 44 [2] 38 71 [2] 16 71 [2] 29 6d }

  condition:
    any of them
}