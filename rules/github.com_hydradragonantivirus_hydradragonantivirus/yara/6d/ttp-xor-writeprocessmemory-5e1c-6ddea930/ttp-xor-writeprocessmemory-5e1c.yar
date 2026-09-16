rule TTP_XOR_WriteProcessMemory_5e1c {
  strings:
    $key_5e1c = { 09 6e [2] 3b 4c [2] 3d 79 [2] 13 79 [2] 2c 65 }

  condition:
    any of them
}