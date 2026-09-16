rule TTP_XOR_WriteProcessMemory_1c45 {
  strings:
    $key_1c45 = { 4b 37 [2] 79 15 [2] 7f 20 [2] 51 20 [2] 6e 3c }

  condition:
    any of them
}