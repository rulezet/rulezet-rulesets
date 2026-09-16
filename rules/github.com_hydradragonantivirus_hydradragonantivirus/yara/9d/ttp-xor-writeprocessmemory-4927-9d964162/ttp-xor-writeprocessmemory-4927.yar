rule TTP_XOR_WriteProcessMemory_4927 {
  strings:
    $key_4927 = { 1e 55 [2] 2c 77 [2] 2a 42 [2] 04 42 [2] 3b 5e }

  condition:
    any of them
}