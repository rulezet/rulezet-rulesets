rule TTP_XOR_WriteProcessMemory_37d9 {
  strings:
    $key_37d9 = { 60 ab [2] 52 89 [2] 54 bc [2] 7a bc [2] 45 a0 }

  condition:
    any of them
}