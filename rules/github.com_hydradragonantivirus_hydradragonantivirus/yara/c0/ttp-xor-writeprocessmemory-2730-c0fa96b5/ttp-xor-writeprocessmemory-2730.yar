rule TTP_XOR_WriteProcessMemory_2730 {
  strings:
    $key_2730 = { 70 42 [2] 42 60 [2] 44 55 [2] 6a 55 [2] 55 49 }

  condition:
    any of them
}