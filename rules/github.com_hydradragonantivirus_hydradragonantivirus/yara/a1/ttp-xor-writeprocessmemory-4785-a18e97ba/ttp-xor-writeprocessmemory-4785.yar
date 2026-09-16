rule TTP_XOR_WriteProcessMemory_4785 {
  strings:
    $key_4785 = { 10 f7 [2] 22 d5 [2] 24 e0 [2] 0a e0 [2] 35 fc }

  condition:
    any of them
}