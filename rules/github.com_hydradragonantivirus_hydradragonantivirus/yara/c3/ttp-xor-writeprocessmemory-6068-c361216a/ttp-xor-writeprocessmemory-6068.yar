rule TTP_XOR_WriteProcessMemory_6068 {
  strings:
    $key_6068 = { 37 1a [2] 05 38 [2] 03 0d [2] 2d 0d [2] 12 11 }

  condition:
    any of them
}