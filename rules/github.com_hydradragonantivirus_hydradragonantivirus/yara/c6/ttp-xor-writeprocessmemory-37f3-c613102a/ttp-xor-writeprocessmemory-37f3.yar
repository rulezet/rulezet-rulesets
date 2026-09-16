rule TTP_XOR_WriteProcessMemory_37f3 {
  strings:
    $key_37f3 = { 60 81 [2] 52 a3 [2] 54 96 [2] 7a 96 [2] 45 8a }

  condition:
    any of them
}