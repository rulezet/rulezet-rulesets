rule TTP_XOR_WriteProcessMemory_5527 {
  strings:
    $key_5527 = { 02 55 [2] 30 77 [2] 36 42 [2] 18 42 [2] 27 5e }

  condition:
    any of them
}