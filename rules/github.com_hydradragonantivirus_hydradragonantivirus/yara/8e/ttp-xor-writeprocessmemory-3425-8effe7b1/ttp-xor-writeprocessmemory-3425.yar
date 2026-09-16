rule TTP_XOR_WriteProcessMemory_3425 {
  strings:
    $key_3425 = { 63 57 [2] 51 75 [2] 57 40 [2] 79 40 [2] 46 5c }

  condition:
    any of them
}