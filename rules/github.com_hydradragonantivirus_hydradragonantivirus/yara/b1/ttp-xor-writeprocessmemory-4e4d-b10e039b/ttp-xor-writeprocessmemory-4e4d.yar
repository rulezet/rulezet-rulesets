rule TTP_XOR_WriteProcessMemory_4e4d {
  strings:
    $key_4e4d = { 19 3f [2] 2b 1d [2] 2d 28 [2] 03 28 [2] 3c 34 }

  condition:
    any of them
}