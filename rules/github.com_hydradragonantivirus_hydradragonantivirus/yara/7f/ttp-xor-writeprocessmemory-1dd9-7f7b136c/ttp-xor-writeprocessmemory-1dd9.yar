rule TTP_XOR_WriteProcessMemory_1dd9 {
  strings:
    $key_1dd9 = { 4a ab [2] 78 89 [2] 7e bc [2] 50 bc [2] 6f a0 }

  condition:
    any of them
}