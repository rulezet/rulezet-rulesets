rule TTP_XOR_WriteProcessMemory_75f2 {
  strings:
    $key_75f2 = { 22 80 [2] 10 a2 [2] 16 97 [2] 38 97 [2] 07 8b }

  condition:
    any of them
}