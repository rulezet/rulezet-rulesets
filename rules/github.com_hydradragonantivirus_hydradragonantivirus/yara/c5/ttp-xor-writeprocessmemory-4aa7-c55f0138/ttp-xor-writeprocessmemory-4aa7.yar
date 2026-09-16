rule TTP_XOR_WriteProcessMemory_4aa7 {
  strings:
    $key_4aa7 = { 1d d5 [2] 2f f7 [2] 29 c2 [2] 07 c2 [2] 38 de }

  condition:
    any of them
}