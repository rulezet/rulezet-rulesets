rule TTP_XOR_WriteProcessMemory_33f2 {
  strings:
    $key_33f2 = { 64 80 [2] 56 a2 [2] 50 97 [2] 7e 97 [2] 41 8b }

  condition:
    any of them
}