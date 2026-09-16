rule TTP_XOR_WriteProcessMemory_5c12 {
  strings:
    $key_5c12 = { 0b 60 [2] 39 42 [2] 3f 77 [2] 11 77 [2] 2e 6b }

  condition:
    any of them
}