rule TTP_XOR_WriteProcessMemory_37f0 {
  strings:
    $key_37f0 = { 60 82 [2] 52 a0 [2] 54 95 [2] 7a 95 [2] 45 89 }

  condition:
    any of them
}