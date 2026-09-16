rule TTP_XOR_WriteProcessMemory_1c72 {
  strings:
    $key_1c72 = { 4b 00 [2] 79 22 [2] 7f 17 [2] 51 17 [2] 6e 0b }

  condition:
    any of them
}