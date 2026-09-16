rule TTP_XOR_WriteProcessMemory_1b25 {
  strings:
    $key_1b25 = { 4c 57 [2] 7e 75 [2] 78 40 [2] 56 40 [2] 69 5c }

  condition:
    any of them
}