rule TTP_XOR_WriteProcessMemory_16f9 {
  strings:
    $key_16f9 = { 41 8b [2] 73 a9 [2] 75 9c [2] 5b 9c [2] 64 80 }

  condition:
    any of them
}