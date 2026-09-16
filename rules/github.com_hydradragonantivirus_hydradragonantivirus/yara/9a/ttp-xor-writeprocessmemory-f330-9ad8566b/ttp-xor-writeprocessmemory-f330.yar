rule TTP_XOR_WriteProcessMemory_f330 {
  strings:
    $key_f330 = { a4 42 [2] 96 60 [2] 90 55 [2] be 55 [2] 81 49 }

  condition:
    any of them
}