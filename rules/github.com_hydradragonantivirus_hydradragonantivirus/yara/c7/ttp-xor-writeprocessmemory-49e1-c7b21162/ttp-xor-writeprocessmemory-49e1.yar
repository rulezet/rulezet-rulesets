rule TTP_XOR_WriteProcessMemory_49e1 {
  strings:
    $key_49e1 = { 1e 93 [2] 2c b1 [2] 2a 84 [2] 04 84 [2] 3b 98 }

  condition:
    any of them
}