rule TTP_XOR_WriteProcessMemory_6f2d {
  strings:
    $key_6f2d = { 38 5f [2] 0a 7d [2] 0c 48 [2] 22 48 [2] 1d 54 }

  condition:
    any of them
}