rule TTP_XOR_WriteProcessMemory_1262 {
  strings:
    $key_1262 = { 45 10 [2] 77 32 [2] 71 07 [2] 5f 07 [2] 60 1b }

  condition:
    any of them
}