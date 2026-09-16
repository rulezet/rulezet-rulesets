rule TTP_XOR_WriteProcessMemory_6246 {
  strings:
    $key_6246 = { 35 34 [2] 07 16 [2] 01 23 [2] 2f 23 [2] 10 3f }

  condition:
    any of them
}