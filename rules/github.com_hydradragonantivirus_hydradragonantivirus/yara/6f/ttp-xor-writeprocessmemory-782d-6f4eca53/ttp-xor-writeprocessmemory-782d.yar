rule TTP_XOR_WriteProcessMemory_782d {
  strings:
    $key_782d = { 2f 5f [2] 1d 7d [2] 1b 48 [2] 35 48 [2] 0a 54 }

  condition:
    any of them
}