rule TTP_XOR_WriteProcessMemory_6db3 {
  strings:
    $key_6db3 = { 3a c1 [2] 08 e3 [2] 0e d6 [2] 20 d6 [2] 1f ca }

  condition:
    any of them
}