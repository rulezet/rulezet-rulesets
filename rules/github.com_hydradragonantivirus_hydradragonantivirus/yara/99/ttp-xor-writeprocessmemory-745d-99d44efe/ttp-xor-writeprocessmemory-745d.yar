rule TTP_XOR_WriteProcessMemory_745d {
  strings:
    $key_745d = { 23 2f [2] 11 0d [2] 17 38 [2] 39 38 [2] 06 24 }

  condition:
    any of them
}