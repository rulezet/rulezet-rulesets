rule TTP_XOR_WriteProcessMemory_1aa7 {
  strings:
    $key_1aa7 = { 4d d5 [2] 7f f7 [2] 79 c2 [2] 57 c2 [2] 68 de }

  condition:
    any of them
}