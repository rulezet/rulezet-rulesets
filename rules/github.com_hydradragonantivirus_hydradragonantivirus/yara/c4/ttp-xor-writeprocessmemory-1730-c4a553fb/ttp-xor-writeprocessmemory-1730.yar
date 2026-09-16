rule TTP_XOR_WriteProcessMemory_1730 {
  strings:
    $key_1730 = { 40 42 [2] 72 60 [2] 74 55 [2] 5a 55 [2] 65 49 }

  condition:
    any of them
}