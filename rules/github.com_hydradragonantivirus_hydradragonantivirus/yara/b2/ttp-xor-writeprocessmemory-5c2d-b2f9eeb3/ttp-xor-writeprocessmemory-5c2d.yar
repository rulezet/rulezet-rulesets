rule TTP_XOR_WriteProcessMemory_5c2d {
  strings:
    $key_5c2d = { 0b 5f [2] 39 7d [2] 3f 48 [2] 11 48 [2] 2e 54 }

  condition:
    any of them
}