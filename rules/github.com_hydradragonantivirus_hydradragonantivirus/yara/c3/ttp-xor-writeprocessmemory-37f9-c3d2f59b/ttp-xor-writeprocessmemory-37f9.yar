rule TTP_XOR_WriteProcessMemory_37f9 {
  strings:
    $key_37f9 = { 60 8b [2] 52 a9 [2] 54 9c [2] 7a 9c [2] 45 80 }

  condition:
    any of them
}