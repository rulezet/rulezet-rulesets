rule TTP_XOR_WriteProcessMemory_1df9 {
  strings:
    $key_1df9 = { 4a 8b [2] 78 a9 [2] 7e 9c [2] 50 9c [2] 6f 80 }

  condition:
    any of them
}