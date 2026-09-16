rule TTP_XOR_WriteProcessMemory_493d {
  strings:
    $key_493d = { 1e 4f [2] 2c 6d [2] 2a 58 [2] 04 58 [2] 3b 44 }

  condition:
    any of them
}