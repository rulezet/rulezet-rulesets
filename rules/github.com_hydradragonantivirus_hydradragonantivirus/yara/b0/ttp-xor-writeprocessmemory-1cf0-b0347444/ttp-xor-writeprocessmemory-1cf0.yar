rule TTP_XOR_WriteProcessMemory_1cf0 {
  strings:
    $key_1cf0 = { 4b 82 [2] 79 a0 [2] 7f 95 [2] 51 95 [2] 6e 89 }

  condition:
    any of them
}