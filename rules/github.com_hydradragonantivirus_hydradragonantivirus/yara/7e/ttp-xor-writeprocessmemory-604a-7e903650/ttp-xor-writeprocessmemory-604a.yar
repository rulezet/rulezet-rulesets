rule TTP_XOR_WriteProcessMemory_604a {
  strings:
    $key_604a = { 37 38 [2] 05 1a [2] 03 2f [2] 2d 2f [2] 12 33 }

  condition:
    any of them
}