rule TTP_XOR_WriteProcessMemory_5e4a {
  strings:
    $key_5e4a = { 09 38 [2] 3b 1a [2] 3d 2f [2] 13 2f [2] 2c 33 }

  condition:
    any of them
}