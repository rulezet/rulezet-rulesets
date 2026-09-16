rule TTP_XOR_WriteProcessMemory_6dd0 {
  strings:
    $key_6dd0 = { 3a a2 [2] 08 80 [2] 0e b5 [2] 20 b5 [2] 1f a9 }

  condition:
    any of them
}