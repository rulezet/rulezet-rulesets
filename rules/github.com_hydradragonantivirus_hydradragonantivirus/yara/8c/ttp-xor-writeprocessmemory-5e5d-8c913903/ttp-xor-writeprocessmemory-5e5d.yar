rule TTP_XOR_WriteProcessMemory_5e5d {
  strings:
    $key_5e5d = { 09 2f [2] 3b 0d [2] 3d 38 [2] 13 38 [2] 2c 24 }

  condition:
    any of them
}