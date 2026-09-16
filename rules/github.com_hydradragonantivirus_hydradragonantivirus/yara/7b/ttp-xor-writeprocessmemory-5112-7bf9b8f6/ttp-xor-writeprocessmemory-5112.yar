rule TTP_XOR_WriteProcessMemory_5112 {
  strings:
    $key_5112 = { 06 60 [2] 34 42 [2] 32 77 [2] 1c 77 [2] 23 6b }

  condition:
    any of them
}