rule TTP_XOR_WriteProcessMemory_6112 {
  strings:
    $key_6112 = { 36 60 [2] 04 42 [2] 02 77 [2] 2c 77 [2] 13 6b }

  condition:
    any of them
}