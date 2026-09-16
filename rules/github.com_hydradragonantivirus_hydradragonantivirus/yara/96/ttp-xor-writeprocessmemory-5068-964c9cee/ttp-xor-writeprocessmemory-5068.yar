rule TTP_XOR_WriteProcessMemory_5068 {
  strings:
    $key_5068 = { 07 1a [2] 35 38 [2] 33 0d [2] 1d 0d [2] 22 11 }

  condition:
    any of them
}