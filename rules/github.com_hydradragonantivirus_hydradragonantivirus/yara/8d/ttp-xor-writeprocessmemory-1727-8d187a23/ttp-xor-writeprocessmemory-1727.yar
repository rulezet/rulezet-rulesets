rule TTP_XOR_WriteProcessMemory_1727 {
  strings:
    $key_1727 = { 40 55 [2] 72 77 [2] 74 42 [2] 5a 42 [2] 65 5e }

  condition:
    any of them
}