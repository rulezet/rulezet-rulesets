rule TTP_XOR_WriteProcessMemory_3b66 {
  strings:
    $key_3b66 = { 6c 14 [2] 5e 36 [2] 58 03 [2] 76 03 [2] 49 1f }

  condition:
    any of them
}