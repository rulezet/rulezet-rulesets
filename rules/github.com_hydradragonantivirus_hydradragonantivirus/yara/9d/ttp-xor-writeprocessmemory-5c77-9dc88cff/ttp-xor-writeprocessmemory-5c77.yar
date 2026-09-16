rule TTP_XOR_WriteProcessMemory_5c77 {
  strings:
    $key_5c77 = { 0b 05 [2] 39 27 [2] 3f 12 [2] 11 12 [2] 2e 0e }

  condition:
    any of them
}