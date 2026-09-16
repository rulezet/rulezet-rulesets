rule TTP_XOR_WriteProcessMemory_1a5d {
  strings:
    $key_1a5d = { 4d 2f [2] 7f 0d [2] 79 38 [2] 57 38 [2] 68 24 }

  condition:
    any of them
}