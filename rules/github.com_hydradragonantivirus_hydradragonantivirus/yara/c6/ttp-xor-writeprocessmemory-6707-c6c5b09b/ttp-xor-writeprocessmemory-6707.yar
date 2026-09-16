rule TTP_XOR_WriteProcessMemory_6707 {
  strings:
    $key_6707 = { 30 75 [2] 02 57 [2] 04 62 [2] 2a 62 [2] 15 7e }

  condition:
    any of them
}