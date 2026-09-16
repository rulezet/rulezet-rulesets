rule TTP_XOR_WriteProcessMemory_4412 {
  strings:
    $key_4412 = { 13 60 [2] 21 42 [2] 27 77 [2] 09 77 [2] 36 6b }

  condition:
    any of them
}