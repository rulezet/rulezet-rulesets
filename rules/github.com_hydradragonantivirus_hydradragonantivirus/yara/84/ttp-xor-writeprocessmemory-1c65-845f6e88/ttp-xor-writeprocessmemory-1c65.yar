rule TTP_XOR_WriteProcessMemory_1c65 {
  strings:
    $key_1c65 = { 4b 17 [2] 79 35 [2] 7f 00 [2] 51 00 [2] 6e 1c }

  condition:
    any of them
}