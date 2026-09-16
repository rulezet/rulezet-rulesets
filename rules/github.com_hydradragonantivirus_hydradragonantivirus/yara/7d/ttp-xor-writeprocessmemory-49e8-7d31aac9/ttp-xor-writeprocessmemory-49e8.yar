rule TTP_XOR_WriteProcessMemory_49e8 {
  strings:
    $key_49e8 = { 1e 9a [2] 2c b8 [2] 2a 8d [2] 04 8d [2] 3b 91 }

  condition:
    any of them
}