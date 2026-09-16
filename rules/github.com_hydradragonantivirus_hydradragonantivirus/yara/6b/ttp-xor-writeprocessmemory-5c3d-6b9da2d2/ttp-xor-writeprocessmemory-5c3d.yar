rule TTP_XOR_WriteProcessMemory_5c3d {
  strings:
    $key_5c3d = { 0b 4f [2] 39 6d [2] 3f 58 [2] 11 58 [2] 2e 44 }

  condition:
    any of them
}