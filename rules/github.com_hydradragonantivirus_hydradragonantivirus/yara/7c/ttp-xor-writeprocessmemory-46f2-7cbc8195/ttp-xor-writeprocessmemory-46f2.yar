rule TTP_XOR_WriteProcessMemory_46f2 {
  strings:
    $key_46f2 = { 11 80 [2] 23 a2 [2] 25 97 [2] 0b 97 [2] 34 8b }

  condition:
    any of them
}