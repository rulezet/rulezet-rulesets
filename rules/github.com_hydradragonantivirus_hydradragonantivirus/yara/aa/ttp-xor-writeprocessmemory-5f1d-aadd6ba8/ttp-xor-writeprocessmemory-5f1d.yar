rule TTP_XOR_WriteProcessMemory_5f1d {
  strings:
    $key_5f1d = { 08 6f [2] 3a 4d [2] 3c 78 [2] 12 78 [2] 2d 64 }

  condition:
    any of them
}