rule TTP_XOR_WriteProcessMemory_1712 {
  strings:
    $key_1712 = { 40 60 [2] 72 42 [2] 74 77 [2] 5a 77 [2] 65 6b }

  condition:
    any of them
}