rule TTP_XOR_WriteProcessMemory_4743 {
  strings:
    $key_4743 = { 10 31 [2] 22 13 [2] 24 26 [2] 0a 26 [2] 35 3a }

  condition:
    any of them
}