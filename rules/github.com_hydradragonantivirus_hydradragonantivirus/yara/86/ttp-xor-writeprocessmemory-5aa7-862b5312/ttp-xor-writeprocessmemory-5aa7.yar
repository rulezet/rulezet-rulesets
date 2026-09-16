rule TTP_XOR_WriteProcessMemory_5aa7 {
  strings:
    $key_5aa7 = { 0d d5 [2] 3f f7 [2] 39 c2 [2] 17 c2 [2] 28 de }

  condition:
    any of them
}