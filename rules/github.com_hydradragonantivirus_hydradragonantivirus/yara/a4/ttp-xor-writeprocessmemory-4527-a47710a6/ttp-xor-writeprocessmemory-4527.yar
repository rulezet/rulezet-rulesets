rule TTP_XOR_WriteProcessMemory_4527 {
  strings:
    $key_4527 = { 12 55 [2] 20 77 [2] 26 42 [2] 08 42 [2] 37 5e }

  condition:
    any of them
}