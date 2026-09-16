rule TTP_XOR_WriteProcessMemory_6dd9 {
  strings:
    $key_6dd9 = { 3a ab [2] 08 89 [2] 0e bc [2] 20 bc [2] 1f a0 }

  condition:
    any of them
}