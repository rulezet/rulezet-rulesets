rule TTP_XOR_WriteProcessMemory_46f9 {
  strings:
    $key_46f9 = { 11 8b [2] 23 a9 [2] 25 9c [2] 0b 9c [2] 34 80 }

  condition:
    any of them
}