rule TTP_XOR_WriteProcessMemory_3085 {
  strings:
    $key_3085 = { 67 f7 [2] 55 d5 [2] 53 e0 [2] 7d e0 [2] 42 fc }

  condition:
    any of them
}