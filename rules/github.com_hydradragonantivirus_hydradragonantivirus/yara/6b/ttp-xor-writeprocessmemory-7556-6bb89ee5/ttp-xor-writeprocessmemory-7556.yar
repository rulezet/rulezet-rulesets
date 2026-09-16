rule TTP_XOR_WriteProcessMemory_7556 {
  strings:
    $key_7556 = { 22 24 [2] 10 06 [2] 16 33 [2] 38 33 [2] 07 2f }

  condition:
    any of them
}