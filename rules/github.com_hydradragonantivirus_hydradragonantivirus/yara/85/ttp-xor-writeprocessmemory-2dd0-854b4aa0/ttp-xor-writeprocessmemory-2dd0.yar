rule TTP_XOR_WriteProcessMemory_2dd0 {
  strings:
    $key_2dd0 = { 7a a2 [2] 48 80 [2] 4e b5 [2] 60 b5 [2] 5f a9 }

  condition:
    any of them
}