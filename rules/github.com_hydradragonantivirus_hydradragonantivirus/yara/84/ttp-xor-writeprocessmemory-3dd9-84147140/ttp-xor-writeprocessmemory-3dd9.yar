rule TTP_XOR_WriteProcessMemory_3dd9 {
  strings:
    $key_3dd9 = { 6a ab [2] 58 89 [2] 5e bc [2] 70 bc [2] 4f a0 }

  condition:
    any of them
}