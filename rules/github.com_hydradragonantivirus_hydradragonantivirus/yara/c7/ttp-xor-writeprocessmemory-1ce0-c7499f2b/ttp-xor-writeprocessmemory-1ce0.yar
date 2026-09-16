rule TTP_XOR_WriteProcessMemory_1ce0 {
  strings:
    $key_1ce0 = { 4b 92 [2] 79 b0 [2] 7f 85 [2] 51 85 [2] 6e 99 }

  condition:
    any of them
}