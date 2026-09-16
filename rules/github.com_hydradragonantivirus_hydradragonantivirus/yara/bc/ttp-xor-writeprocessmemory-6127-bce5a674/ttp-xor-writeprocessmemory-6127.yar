rule TTP_XOR_WriteProcessMemory_6127 {
  strings:
    $key_6127 = { 36 55 [2] 04 77 [2] 02 42 [2] 2c 42 [2] 13 5e }

  condition:
    any of them
}