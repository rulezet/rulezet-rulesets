rule TTP_XOR_WriteProcessMemory_27f9 {
  strings:
    $key_27f9 = { 70 8b [2] 42 a9 [2] 44 9c [2] 6a 9c [2] 55 80 }

  condition:
    any of them
}