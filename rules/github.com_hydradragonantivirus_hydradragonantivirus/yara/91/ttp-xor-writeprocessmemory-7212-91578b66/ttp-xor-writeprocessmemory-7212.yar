rule TTP_XOR_WriteProcessMemory_7212 {
  strings:
    $key_7212 = { 25 60 [2] 17 42 [2] 11 77 [2] 3f 77 [2] 00 6b }

  condition:
    any of them
}