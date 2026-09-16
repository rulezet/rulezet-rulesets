rule TTP_XOR_WriteProcessMemory_0b3d {
  strings:
    $key_0b3d = { 5c 4f [2] 6e 6d [2] 68 58 [2] 46 58 [2] 79 44 }

  condition:
    any of them
}