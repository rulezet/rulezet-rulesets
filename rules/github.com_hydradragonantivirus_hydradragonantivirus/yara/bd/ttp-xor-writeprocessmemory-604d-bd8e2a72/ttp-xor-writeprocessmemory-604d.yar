rule TTP_XOR_WriteProcessMemory_604d {
  strings:
    $key_604d = { 37 3f [2] 05 1d [2] 03 28 [2] 2d 28 [2] 12 34 }

  condition:
    any of them
}