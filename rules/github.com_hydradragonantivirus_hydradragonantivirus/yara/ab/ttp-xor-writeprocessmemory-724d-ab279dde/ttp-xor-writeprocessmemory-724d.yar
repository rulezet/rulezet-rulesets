rule TTP_XOR_WriteProcessMemory_724d {
  strings:
    $key_724d = { 25 3f [2] 17 1d [2] 11 28 [2] 3f 28 [2] 00 34 }

  condition:
    any of them
}