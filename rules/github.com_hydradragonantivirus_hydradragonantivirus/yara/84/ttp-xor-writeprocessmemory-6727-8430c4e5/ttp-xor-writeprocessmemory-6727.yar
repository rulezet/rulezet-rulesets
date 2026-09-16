rule TTP_XOR_WriteProcessMemory_6727 {
  strings:
    $key_6727 = { 30 55 [2] 02 77 [2] 04 42 [2] 2a 42 [2] 15 5e }

  condition:
    any of them
}