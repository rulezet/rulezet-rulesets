rule TTP_XOR_WriteProcessMemory_74f9 {
  strings:
    $key_74f9 = { 23 8b [2] 11 a9 [2] 17 9c [2] 39 9c [2] 06 80 }

  condition:
    any of them
}