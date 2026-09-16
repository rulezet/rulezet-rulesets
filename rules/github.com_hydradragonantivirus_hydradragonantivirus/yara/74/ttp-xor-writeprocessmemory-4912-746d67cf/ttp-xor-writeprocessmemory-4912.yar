rule TTP_XOR_WriteProcessMemory_4912 {
  strings:
    $key_4912 = { 1e 60 [2] 2c 42 [2] 2a 77 [2] 04 77 [2] 3b 6b }

  condition:
    any of them
}