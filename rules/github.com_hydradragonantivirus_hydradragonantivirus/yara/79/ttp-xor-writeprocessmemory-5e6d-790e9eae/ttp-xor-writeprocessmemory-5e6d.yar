rule TTP_XOR_WriteProcessMemory_5e6d {
  strings:
    $key_5e6d = { 09 1f [2] 3b 3d [2] 3d 08 [2] 13 08 [2] 2c 14 }

  condition:
    any of them
}