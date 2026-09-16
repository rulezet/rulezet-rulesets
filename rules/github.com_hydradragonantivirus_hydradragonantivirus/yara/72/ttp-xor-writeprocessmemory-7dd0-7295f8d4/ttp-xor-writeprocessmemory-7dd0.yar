rule TTP_XOR_WriteProcessMemory_7dd0 {
  strings:
    $key_7dd0 = { 2a a2 [2] 18 80 [2] 1e b5 [2] 30 b5 [2] 0f a9 }

  condition:
    any of them
}