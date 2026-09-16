rule TTP_XOR_WriteProcessMemory_784c {
  strings:
    $key_784c = { 2f 3e [2] 1d 1c [2] 1b 29 [2] 35 29 [2] 0a 35 }

  condition:
    any of them
}