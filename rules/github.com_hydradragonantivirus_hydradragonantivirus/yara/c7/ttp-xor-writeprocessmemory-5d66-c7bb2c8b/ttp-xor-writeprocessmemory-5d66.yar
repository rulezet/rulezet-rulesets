rule TTP_XOR_WriteProcessMemory_5d66 {
  strings:
    $key_5d66 = { 0a 14 [2] 38 36 [2] 3e 03 [2] 10 03 [2] 2f 1f }

  condition:
    any of them
}