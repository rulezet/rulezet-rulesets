rule TTP_XOR_WriteProcessMemory_49e0 {
  strings:
    $key_49e0 = { 1e 92 [2] 2c b0 [2] 2a 85 [2] 04 85 [2] 3b 99 }

  condition:
    any of them
}