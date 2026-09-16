rule TTP_XOR_WriteProcessMemory_3343 {
  strings:
    $key_3343 = { 64 31 [2] 56 13 [2] 50 26 [2] 7e 26 [2] 41 3a }

  condition:
    any of them
}