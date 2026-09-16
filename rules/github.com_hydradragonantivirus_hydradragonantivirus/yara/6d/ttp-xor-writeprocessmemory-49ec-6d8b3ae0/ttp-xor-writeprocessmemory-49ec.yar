rule TTP_XOR_WriteProcessMemory_49ec {
  strings:
    $key_49ec = { 1e 9e [2] 2c bc [2] 2a 89 [2] 04 89 [2] 3b 95 }

  condition:
    any of them
}