rule TTP_XOR_WriteProcessMemory_4a2d {
  strings:
    $key_4a2d = { 1d 5f [2] 2f 7d [2] 29 48 [2] 07 48 [2] 38 54 }

  condition:
    any of them
}