rule TTP_XOR_WriteProcessMemory_7eba {
  strings:
    $key_7eba = { 29 c8 [2] 1b ea [2] 1d df [2] 33 df [2] 0c c3 }

  condition:
    any of them
}