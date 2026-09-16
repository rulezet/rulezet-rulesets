rule TTP_XOR_WriteProcessMemory_77f2 {
  strings:
    $key_77f2 = { 20 80 [2] 12 a2 [2] 14 97 [2] 3a 97 [2] 05 8b }

  condition:
    any of them
}