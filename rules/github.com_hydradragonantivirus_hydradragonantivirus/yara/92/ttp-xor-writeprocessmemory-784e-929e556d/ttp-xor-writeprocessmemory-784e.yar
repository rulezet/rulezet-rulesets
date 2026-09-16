rule TTP_XOR_WriteProcessMemory_784e {
  strings:
    $key_784e = { 2f 3c [2] 1d 1e [2] 1b 2b [2] 35 2b [2] 0a 37 }

  condition:
    any of them
}