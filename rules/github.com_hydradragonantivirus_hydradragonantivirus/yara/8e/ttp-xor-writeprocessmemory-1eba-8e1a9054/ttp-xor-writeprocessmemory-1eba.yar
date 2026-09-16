rule TTP_XOR_WriteProcessMemory_1eba {
  strings:
    $key_1eba = { 49 c8 [2] 7b ea [2] 7d df [2] 53 df [2] 6c c3 }

  condition:
    any of them
}