rule TTP_XOR_WriteProcessMemory_40f9 {
  strings:
    $key_40f9 = { 17 8b [2] 25 a9 [2] 23 9c [2] 0d 9c [2] 32 80 }

  condition:
    any of them
}