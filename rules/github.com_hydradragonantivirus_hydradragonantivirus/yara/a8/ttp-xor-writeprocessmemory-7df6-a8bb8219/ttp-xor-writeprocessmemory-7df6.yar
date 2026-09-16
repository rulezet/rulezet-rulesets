rule TTP_XOR_WriteProcessMemory_7df6 {
  strings:
    $key_7df6 = { 2a 84 [2] 18 a6 [2] 1e 93 [2] 30 93 [2] 0f 8f }

  condition:
    any of them
}