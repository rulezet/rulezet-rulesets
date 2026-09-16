rule TTP_XOR_WriteProcessMemory_7dd9 {
  strings:
    $key_7dd9 = { 2a ab [2] 18 89 [2] 1e bc [2] 30 bc [2] 0f a0 }

  condition:
    any of them
}