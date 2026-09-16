rule TTP_XOR_WriteProcessMemory_4330 {
  strings:
    $key_4330 = { 14 42 [2] 26 60 [2] 20 55 [2] 0e 55 [2] 31 49 }

  condition:
    any of them
}