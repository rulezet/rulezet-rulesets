rule TTP_XOR_WriteProcessMemory_4406 {
  strings:
    $key_4406 = { 13 74 [2] 21 56 [2] 27 63 [2] 09 63 [2] 36 7f }

  condition:
    any of them
}