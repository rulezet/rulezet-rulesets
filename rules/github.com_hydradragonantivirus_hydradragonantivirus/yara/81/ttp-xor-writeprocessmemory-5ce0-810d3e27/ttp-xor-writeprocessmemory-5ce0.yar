rule TTP_XOR_WriteProcessMemory_5ce0 {
  strings:
    $key_5ce0 = { 0b 92 [2] 39 b0 [2] 3f 85 [2] 11 85 [2] 2e 99 }

  condition:
    any of them
}