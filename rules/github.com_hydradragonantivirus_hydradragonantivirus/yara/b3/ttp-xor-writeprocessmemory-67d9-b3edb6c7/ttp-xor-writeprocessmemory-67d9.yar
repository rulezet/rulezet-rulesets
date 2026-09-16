rule TTP_XOR_WriteProcessMemory_67d9 {
  strings:
    $key_67d9 = { 30 ab [2] 02 89 [2] 04 bc [2] 2a bc [2] 15 a0 }

  condition:
    any of them
}