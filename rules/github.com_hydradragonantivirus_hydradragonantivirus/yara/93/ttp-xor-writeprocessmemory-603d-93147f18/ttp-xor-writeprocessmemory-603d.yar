rule TTP_XOR_WriteProcessMemory_603d {
  strings:
    $key_603d = { 37 4f [2] 05 6d [2] 03 58 [2] 2d 58 [2] 12 44 }

  condition:
    any of them
}