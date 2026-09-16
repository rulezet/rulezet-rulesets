rule TTP_XOR_WriteProcessMemory_10f9 {
  strings:
    $key_10f9 = { 47 8b [2] 75 a9 [2] 73 9c [2] 5d 9c [2] 62 80 }

  condition:
    any of them
}