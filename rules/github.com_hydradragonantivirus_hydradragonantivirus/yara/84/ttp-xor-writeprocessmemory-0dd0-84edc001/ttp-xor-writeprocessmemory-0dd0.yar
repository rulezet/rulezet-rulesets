rule TTP_XOR_WriteProcessMemory_0dd0 {
  strings:
    $key_0dd0 = { 5a a2 [2] 68 80 [2] 6e b5 [2] 40 b5 [2] 7f a9 }

  condition:
    any of them
}