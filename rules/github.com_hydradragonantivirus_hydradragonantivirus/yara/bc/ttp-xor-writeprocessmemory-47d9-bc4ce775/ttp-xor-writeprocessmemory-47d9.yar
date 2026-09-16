rule TTP_XOR_WriteProcessMemory_47d9 {
  strings:
    $key_47d9 = { 10 ab [2] 22 89 [2] 24 bc [2] 0a bc [2] 35 a0 }

  condition:
    any of them
}