rule TTP_XOR_WriteProcessMemory_5506 {
  strings:
    $key_5506 = { 02 74 [2] 30 56 [2] 36 63 [2] 18 63 [2] 27 7f }

  condition:
    any of them
}