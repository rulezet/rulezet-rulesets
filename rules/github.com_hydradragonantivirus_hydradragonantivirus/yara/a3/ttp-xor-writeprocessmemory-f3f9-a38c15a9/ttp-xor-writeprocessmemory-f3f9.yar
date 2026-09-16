rule TTP_XOR_WriteProcessMemory_f3f9 {
  strings:
    $key_f3f9 = { a4 8b [2] 96 a9 [2] 90 9c [2] be 9c [2] 81 80 }

  condition:
    any of them
}