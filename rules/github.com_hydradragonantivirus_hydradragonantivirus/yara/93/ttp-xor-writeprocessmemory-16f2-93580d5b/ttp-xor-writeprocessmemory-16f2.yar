rule TTP_XOR_WriteProcessMemory_16f2 {
  strings:
    $key_16f2 = { 41 80 [2] 73 a2 [2] 75 97 [2] 5b 97 [2] 64 8b }

  condition:
    any of them
}