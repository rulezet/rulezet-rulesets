rule TTP_XOR_WriteProcessMemory_1c63 {
  strings:
    $key_1c63 = { 4b 11 [2] 79 33 [2] 7f 06 [2] 51 06 [2] 6e 1a }

  condition:
    any of them
}