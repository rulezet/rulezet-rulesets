rule TTP_XOR_WriteProcessMemory_4db3 {
  strings:
    $key_4db3 = { 1a c1 [2] 28 e3 [2] 2e d6 [2] 00 d6 [2] 3f ca }

  condition:
    any of them
}