rule TTP_XOR_WriteProcessMemory_7e3d {
  strings:
    $key_7e3d = { 29 4f [2] 1b 6d [2] 1d 58 [2] 33 58 [2] 0c 44 }

  condition:
    any of them
}