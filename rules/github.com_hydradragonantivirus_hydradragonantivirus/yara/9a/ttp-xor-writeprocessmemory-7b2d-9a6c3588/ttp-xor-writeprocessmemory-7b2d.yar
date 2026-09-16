rule TTP_XOR_WriteProcessMemory_7b2d {
  strings:
    $key_7b2d = { 2c 5f [2] 1e 7d [2] 18 48 [2] 36 48 [2] 09 54 }

  condition:
    any of them
}