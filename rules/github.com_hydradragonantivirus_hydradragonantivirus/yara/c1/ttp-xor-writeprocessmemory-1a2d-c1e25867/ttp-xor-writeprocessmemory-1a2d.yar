rule TTP_XOR_WriteProcessMemory_1a2d {
  strings:
    $key_1a2d = { 4d 5f [2] 7f 7d [2] 79 48 [2] 57 48 [2] 68 54 }

  condition:
    any of them
}