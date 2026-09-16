rule TTP_XOR_WriteProcessMemory_7db3 {
  strings:
    $key_7db3 = { 2a c1 [2] 18 e3 [2] 1e d6 [2] 30 d6 [2] 0f ca }

  condition:
    any of them
}