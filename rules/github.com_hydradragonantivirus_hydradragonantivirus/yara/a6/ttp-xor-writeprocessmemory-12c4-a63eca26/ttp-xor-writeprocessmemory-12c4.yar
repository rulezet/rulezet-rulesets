rule TTP_XOR_WriteProcessMemory_12c4 {
  strings:
    $key_12c4 = { 45 b6 [2] 77 94 [2] 71 a1 [2] 5f a1 [2] 60 bd }

  condition:
    any of them
}