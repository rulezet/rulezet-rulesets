rule TTP_XOR_WriteProcessMemory_49e3 {
  strings:
    $key_49e3 = { 1e 91 [2] 2c b3 [2] 2a 86 [2] 04 86 [2] 3b 9a }

  condition:
    any of them
}