rule TTP_XOR_WriteProcessMemory_1cf1 {
  strings:
    $key_1cf1 = { 4b 83 [2] 79 a1 [2] 7f 94 [2] 51 94 [2] 6e 88 }

  condition:
    any of them
}