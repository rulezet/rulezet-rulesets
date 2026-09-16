rule TTP_XOR_WriteProcessMemory_1dd0 {
  strings:
    $key_1dd0 = { 4a a2 [2] 78 80 [2] 7e b5 [2] 50 b5 [2] 6f a9 }

  condition:
    any of them
}