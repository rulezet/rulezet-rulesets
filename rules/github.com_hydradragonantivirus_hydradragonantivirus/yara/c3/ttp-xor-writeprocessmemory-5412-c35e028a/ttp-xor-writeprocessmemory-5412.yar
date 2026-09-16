rule TTP_XOR_WriteProcessMemory_5412 {
  strings:
    $key_5412 = { 03 60 [2] 31 42 [2] 37 77 [2] 19 77 [2] 26 6b }

  condition:
    any of them
}