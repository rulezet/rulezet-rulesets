rule TTP_XOR_WriteProcessMemory_dec7 {
  strings:
    $key_dec7 = { 89 b5 [2] bb 97 [2] bd a2 [2] 93 a2 [2] ac be }

  condition:
    any of them
}