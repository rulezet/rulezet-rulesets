rule TTP_XOR_WriteProcessMemory_784d {
  strings:
    $key_784d = { 2f 3f [2] 1d 1d [2] 1b 28 [2] 35 28 [2] 0a 34 }

  condition:
    any of them
}