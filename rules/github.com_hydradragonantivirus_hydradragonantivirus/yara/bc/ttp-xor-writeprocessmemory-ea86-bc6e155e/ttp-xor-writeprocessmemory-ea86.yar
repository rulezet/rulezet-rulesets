rule TTP_XOR_WriteProcessMemory_ea86 {
  strings:
    $key_ea86 = { bd f4 [2] 8f d6 [2] 89 e3 [2] a7 e3 [2] 98 ff }

  condition:
    any of them
}