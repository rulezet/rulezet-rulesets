rule TTP_XOR_WriteProcessMemory_2aa7 {
  strings:
    $key_2aa7 = { 7d d5 [2] 4f f7 [2] 49 c2 [2] 67 c2 [2] 58 de }

  condition:
    any of them
}