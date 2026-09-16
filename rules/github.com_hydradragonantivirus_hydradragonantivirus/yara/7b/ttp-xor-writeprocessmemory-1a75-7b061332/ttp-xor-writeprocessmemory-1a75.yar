rule TTP_XOR_WriteProcessMemory_1a75 {
  strings:
    $key_1a75 = { 4d 07 [2] 7f 25 [2] 79 10 [2] 57 10 [2] 68 0c }

  condition:
    any of them
}