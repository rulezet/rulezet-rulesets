rule TTP_XOR_WriteProcessMemory_22f2 {
  strings:
    $key_22f2 = { 75 80 [2] 47 a2 [2] 41 97 [2] 6f 97 [2] 50 8b }

  condition:
    any of them
}