rule TTP_XOR_WriteProcessMemory_5cf1 {
  strings:
    $key_5cf1 = { 0b 83 [2] 39 a1 [2] 3f 94 [2] 11 94 [2] 2e 88 }

  condition:
    any of them
}