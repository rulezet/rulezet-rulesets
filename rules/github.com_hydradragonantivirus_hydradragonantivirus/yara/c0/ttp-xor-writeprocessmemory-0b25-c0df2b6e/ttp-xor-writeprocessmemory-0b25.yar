rule TTP_XOR_WriteProcessMemory_0b25 {
  strings:
    $key_0b25 = { 5c 57 [2] 6e 75 [2] 68 40 [2] 46 40 [2] 79 5c }

  condition:
    any of them
}