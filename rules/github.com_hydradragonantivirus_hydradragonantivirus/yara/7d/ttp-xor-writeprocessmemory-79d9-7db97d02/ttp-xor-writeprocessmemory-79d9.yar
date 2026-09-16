rule TTP_XOR_WriteProcessMemory_79d9 {
  strings:
    $key_79d9 = { 2e ab [2] 1c 89 [2] 1a bc [2] 34 bc [2] 0b a0 }

  condition:
    any of them
}