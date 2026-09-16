rule TTP_XOR_WriteProcessMemory_4085 {
  strings:
    $key_4085 = { 17 f7 [2] 25 d5 [2] 23 e0 [2] 0d e0 [2] 32 fc }

  condition:
    any of them
}