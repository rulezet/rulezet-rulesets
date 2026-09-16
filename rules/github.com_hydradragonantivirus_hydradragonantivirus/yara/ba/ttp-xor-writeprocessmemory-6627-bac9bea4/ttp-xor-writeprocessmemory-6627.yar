rule TTP_XOR_WriteProcessMemory_6627 {
  strings:
    $key_6627 = { 31 55 [2] 03 77 [2] 05 42 [2] 2b 42 [2] 14 5e }

  condition:
    any of them
}