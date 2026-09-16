rule TTP_XOR_WriteProcessMemory_1a4d {
  strings:
    $key_1a4d = { 4d 3f [2] 7f 1d [2] 79 28 [2] 57 28 [2] 68 34 }

  condition:
    any of them
}