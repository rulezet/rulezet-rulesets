rule TTP_XOR_WriteProcessMemory_17d9 {
  strings:
    $key_17d9 = { 40 ab [2] 72 89 [2] 74 bc [2] 5a bc [2] 65 a0 }

  condition:
    any of them
}