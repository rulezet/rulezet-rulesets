rule TTP_XOR_WriteProcessMemory_4916 {
  strings:
    $key_4916 = { 1e 64 [2] 2c 46 [2] 2a 73 [2] 04 73 [2] 3b 6f }

  condition:
    any of them
}