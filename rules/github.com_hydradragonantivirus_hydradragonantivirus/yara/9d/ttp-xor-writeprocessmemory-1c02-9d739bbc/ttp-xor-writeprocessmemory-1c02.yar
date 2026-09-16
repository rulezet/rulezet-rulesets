rule TTP_XOR_WriteProcessMemory_1c02 {
  strings:
    $key_1c02 = { 4b 70 [2] 79 52 [2] 7f 67 [2] 51 67 [2] 6e 7b }

  condition:
    any of them
}