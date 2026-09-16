rule TTP_XOR_WriteProcessMemory_6e3d {
  strings:
    $key_6e3d = { 39 4f [2] 0b 6d [2] 0d 58 [2] 23 58 [2] 1c 44 }

  condition:
    any of them
}