rule TTP_XOR_WriteProcessMemory_ea80 {
  strings:
    $key_ea80 = { bd f2 [2] 8f d0 [2] 89 e5 [2] a7 e5 [2] 98 f9 }

  condition:
    any of them
}