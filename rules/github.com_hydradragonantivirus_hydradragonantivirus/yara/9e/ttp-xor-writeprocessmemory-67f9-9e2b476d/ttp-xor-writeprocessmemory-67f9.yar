rule TTP_XOR_WriteProcessMemory_67f9 {
  strings:
    $key_67f9 = { 30 8b [2] 02 a9 [2] 04 9c [2] 2a 9c [2] 15 80 }

  condition:
    any of them
}