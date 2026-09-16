rule TTP_XOR_WriteProcessMemory_494a {
  strings:
    $key_494a = { 1e 38 [2] 2c 1a [2] 2a 2f [2] 04 2f [2] 3b 33 }

  condition:
    any of them
}