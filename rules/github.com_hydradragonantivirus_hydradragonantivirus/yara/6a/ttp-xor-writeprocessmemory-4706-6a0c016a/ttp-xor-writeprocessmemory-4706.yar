rule TTP_XOR_WriteProcessMemory_4706 {
  strings:
    $key_4706 = { 10 74 [2] 22 56 [2] 24 63 [2] 0a 63 [2] 35 7f }

  condition:
    any of them
}