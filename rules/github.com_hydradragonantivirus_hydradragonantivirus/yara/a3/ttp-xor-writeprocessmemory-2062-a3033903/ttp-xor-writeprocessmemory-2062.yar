rule TTP_XOR_WriteProcessMemory_2062 {
  strings:
    $key_2062 = { 77 10 [2] 45 32 [2] 43 07 [2] 6d 07 [2] 52 1b }

  condition:
    any of them
}