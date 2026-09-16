rule TTP_XOR_WriteProcessMemory_7112 {
  strings:
    $key_7112 = { 26 60 [2] 14 42 [2] 12 77 [2] 3c 77 [2] 03 6b }

  condition:
    any of them
}