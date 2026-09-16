rule TTP_XOR_WriteProcessMemory_3330 {
  strings:
    $key_3330 = { 64 42 [2] 56 60 [2] 50 55 [2] 7e 55 [2] 41 49 }

  condition:
    any of them
}