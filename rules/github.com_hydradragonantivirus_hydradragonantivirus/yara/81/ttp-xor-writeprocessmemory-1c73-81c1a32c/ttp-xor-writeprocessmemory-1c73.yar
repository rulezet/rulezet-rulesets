rule TTP_XOR_WriteProcessMemory_1c73 {
  strings:
    $key_1c73 = { 4b 01 [2] 79 23 [2] 7f 16 [2] 51 16 [2] 6e 0a }

  condition:
    any of them
}