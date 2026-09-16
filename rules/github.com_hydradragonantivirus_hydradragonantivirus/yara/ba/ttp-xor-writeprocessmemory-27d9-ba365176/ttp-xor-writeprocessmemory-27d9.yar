rule TTP_XOR_WriteProcessMemory_27d9 {
  strings:
    $key_27d9 = { 70 ab [2] 42 89 [2] 44 bc [2] 6a bc [2] 55 a0 }

  condition:
    any of them
}