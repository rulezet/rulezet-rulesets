rule TTP_XOR_WriteProcessMemory_2dd9 {
  strings:
    $key_2dd9 = { 7a ab [2] 48 89 [2] 4e bc [2] 60 bc [2] 5f a0 }

  condition:
    any of them
}