rule TTP_XOR_WriteProcessMemory_4eba {
  strings:
    $key_4eba = { 19 c8 [2] 2b ea [2] 2d df [2] 03 df [2] 3c c3 }

  condition:
    any of them
}