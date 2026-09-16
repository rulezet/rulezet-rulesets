rule TTP_XOR_WriteProcessMemory_6f48 {
  strings:
    $key_6f48 = { 38 3a [2] 0a 18 [2] 0c 2d [2] 22 2d [2] 1d 31 }

  condition:
    any of them
}