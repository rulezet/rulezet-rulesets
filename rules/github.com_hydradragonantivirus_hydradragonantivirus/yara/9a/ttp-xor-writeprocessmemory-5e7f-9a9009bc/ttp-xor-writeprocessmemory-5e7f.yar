rule TTP_XOR_WriteProcessMemory_5e7f {
  strings:
    $key_5e7f = { 09 0d [2] 3b 2f [2] 3d 1a [2] 13 1a [2] 2c 06 }

  condition:
    any of them
}