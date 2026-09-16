rule TTP_XOR_WriteProcessMemory_6d66 {
  strings:
    $key_6d66 = { 3a 14 [2] 08 36 [2] 0e 03 [2] 20 03 [2] 1f 1f }

  condition:
    any of them
}