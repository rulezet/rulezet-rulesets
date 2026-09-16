rule TTP_XOR_WriteProcessMemory_0b2d {
  strings:
    $key_0b2d = { 5c 5f [2] 6e 7d [2] 68 48 [2] 46 48 [2] 79 54 }

  condition:
    any of them
}