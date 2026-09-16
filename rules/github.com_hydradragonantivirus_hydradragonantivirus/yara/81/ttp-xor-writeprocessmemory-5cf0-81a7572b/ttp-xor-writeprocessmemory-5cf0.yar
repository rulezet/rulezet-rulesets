rule TTP_XOR_WriteProcessMemory_5cf0 {
  strings:
    $key_5cf0 = { 0b 82 [2] 39 a0 [2] 3f 95 [2] 11 95 [2] 2e 89 }

  condition:
    any of them
}