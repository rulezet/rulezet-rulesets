rule TTP_XOR_WriteProcessMemory_384d {
  strings:
    $key_384d = { 6f 3f [2] 5d 1d [2] 5b 28 [2] 75 28 [2] 4a 34 }

  condition:
    any of them
}