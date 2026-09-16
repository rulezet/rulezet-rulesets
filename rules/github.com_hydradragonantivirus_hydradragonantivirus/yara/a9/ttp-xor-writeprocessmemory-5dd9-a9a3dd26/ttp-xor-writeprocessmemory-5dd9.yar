rule TTP_XOR_WriteProcessMemory_5dd9 {
  strings:
    $key_5dd9 = { 0a ab [2] 38 89 [2] 3e bc [2] 10 bc [2] 2f a0 }

  condition:
    any of them
}