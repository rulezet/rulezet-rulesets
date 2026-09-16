rule TTP_XOR_WriteProcessMemory_29d9 {
  strings:
    $key_29d9 = { 7e ab [2] 4c 89 [2] 4a bc [2] 64 bc [2] 5b a0 }

  condition:
    any of them
}