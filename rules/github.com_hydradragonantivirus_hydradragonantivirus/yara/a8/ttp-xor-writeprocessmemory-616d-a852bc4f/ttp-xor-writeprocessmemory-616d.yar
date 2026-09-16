rule TTP_XOR_WriteProcessMemory_616d {
  strings:
    $key_616d = { 36 1f [2] 04 3d [2] 02 08 [2] 2c 08 [2] 13 14 }

  condition:
    any of them
}