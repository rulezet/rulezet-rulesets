rule TTP_XOR_WriteProcessMemory_49e6 {
  strings:
    $key_49e6 = { 1e 94 [2] 2c b6 [2] 2a 83 [2] 04 83 [2] 3b 9f }

  condition:
    any of them
}