rule TTP_XOR_WriteProcessMemory_22f9 {
  strings:
    $key_22f9 = { 75 8b [2] 47 a9 [2] 41 9c [2] 6f 9c [2] 50 80 }

  condition:
    any of them
}