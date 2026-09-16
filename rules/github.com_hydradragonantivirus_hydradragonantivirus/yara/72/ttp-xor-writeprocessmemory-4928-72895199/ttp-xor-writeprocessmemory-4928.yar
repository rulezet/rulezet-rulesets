rule TTP_XOR_WriteProcessMemory_4928 {
  strings:
    $key_4928 = { 1e 5a [2] 2c 78 [2] 2a 4d [2] 04 4d [2] 3b 51 }

  condition:
    any of them
}