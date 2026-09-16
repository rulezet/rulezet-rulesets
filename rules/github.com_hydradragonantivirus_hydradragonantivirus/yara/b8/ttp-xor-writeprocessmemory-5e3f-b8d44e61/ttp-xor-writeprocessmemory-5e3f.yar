rule TTP_XOR_WriteProcessMemory_5e3f {
  strings:
    $key_5e3f = { 09 4d [2] 3b 6f [2] 3d 5a [2] 13 5a [2] 2c 46 }

  condition:
    any of them
}