rule TTP_XOR_WriteProcessMemory_1db3 {
  strings:
    $key_1db3 = { 4a c1 [2] 78 e3 [2] 7e d6 [2] 50 d6 [2] 6f ca }

  condition:
    any of them
}