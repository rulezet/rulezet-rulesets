rule TTP_XOR_WriteProcessMemory_5df6 {
  strings:
    $key_5df6 = { 0a 84 [2] 38 a6 [2] 3e 93 [2] 10 93 [2] 2f 8f }

  condition:
    any of them
}