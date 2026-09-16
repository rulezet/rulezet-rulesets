rule TTP_XOR_WriteProcessMemory_57c7 {
  strings:
    $key_57c7 = { 00 b5 [2] 32 97 [2] 34 a2 [2] 1a a2 [2] 25 be }

  condition:
    any of them
}