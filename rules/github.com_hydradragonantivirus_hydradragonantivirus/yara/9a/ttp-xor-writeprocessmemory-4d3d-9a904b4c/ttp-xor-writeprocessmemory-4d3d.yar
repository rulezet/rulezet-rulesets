rule TTP_XOR_WriteProcessMemory_4d3d {
  strings:
    $key_4d3d = { 1a 4f [2] 28 6d [2] 2e 58 [2] 00 58 [2] 3f 44 }

  condition:
    any of them
}