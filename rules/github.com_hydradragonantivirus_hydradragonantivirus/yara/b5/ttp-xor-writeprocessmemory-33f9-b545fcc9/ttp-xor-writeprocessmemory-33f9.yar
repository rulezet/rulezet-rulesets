rule TTP_XOR_WriteProcessMemory_33f9 {
  strings:
    $key_33f9 = { 64 8b [2] 56 a9 [2] 50 9c [2] 7e 9c [2] 41 80 }

  condition:
    any of them
}