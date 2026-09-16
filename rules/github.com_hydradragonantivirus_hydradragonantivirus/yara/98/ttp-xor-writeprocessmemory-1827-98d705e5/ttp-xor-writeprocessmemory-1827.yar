rule TTP_XOR_WriteProcessMemory_1827 {
  strings:
    $key_1827 = { 4f 55 [2] 7d 77 [2] 7b 42 [2] 55 42 [2] 6a 5e }

  condition:
    any of them
}