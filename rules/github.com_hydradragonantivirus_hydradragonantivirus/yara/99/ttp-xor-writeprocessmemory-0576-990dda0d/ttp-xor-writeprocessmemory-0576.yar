rule TTP_XOR_WriteProcessMemory_0576 {
  strings:
    $key_0576 = { 52 04 [2] 60 26 [2] 66 13 [2] 48 13 [2] 77 0f }

  condition:
    any of them
}