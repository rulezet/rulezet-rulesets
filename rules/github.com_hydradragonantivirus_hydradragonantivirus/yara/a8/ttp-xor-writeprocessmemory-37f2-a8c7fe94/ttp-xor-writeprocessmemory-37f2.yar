rule TTP_XOR_WriteProcessMemory_37f2 {
  strings:
    $key_37f2 = { 60 80 [2] 52 a2 [2] 54 97 [2] 7a 97 [2] 45 8b }

  condition:
    any of them
}