rule TTP_XOR_WriteProcessMemory_5e4c {
  strings:
    $key_5e4c = { 09 3e [2] 3b 1c [2] 3d 29 [2] 13 29 [2] 2c 35 }

  condition:
    any of them
}