rule TTP_XOR_WriteProcessMemory_4967 {
  strings:
    $key_4967 = { 1e 15 [2] 2c 37 [2] 2a 02 [2] 04 02 [2] 3b 1e }

  condition:
    any of them
}