rule TTP_XOR_WriteProcessMemory_1c22 {
  strings:
    $key_1c22 = { 4b 50 [2] 79 72 [2] 7f 47 [2] 51 47 [2] 6e 5b }

  condition:
    any of them
}