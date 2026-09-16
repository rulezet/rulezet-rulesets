rule TTP_XOR_WriteProcessMemory_2700 {
  strings:
    $key_2700 = { 70 72 [2] 42 50 [2] 44 65 [2] 6a 65 [2] 55 79 }

  condition:
    any of them
}