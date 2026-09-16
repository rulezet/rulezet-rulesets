rule TTP_XOR_WriteProcessMemory_1a65 {
  strings:
    $key_1a65 = { 4d 17 [2] 7f 35 [2] 79 00 [2] 57 00 [2] 68 1c }

  condition:
    any of them
}