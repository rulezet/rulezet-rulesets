rule TTP_XOR_WriteProcessMemory_5f0d {
  strings:
    $key_5f0d = { 08 7f [2] 3a 5d [2] 3c 68 [2] 12 68 [2] 2d 74 }

  condition:
    any of them
}