rule TTP_XOR_WriteProcessMemory_8727 {
  strings:
    $key_8727 = { d0 55 [2] e2 77 [2] e4 42 [2] ca 42 [2] f5 5e }

  condition:
    any of them
}