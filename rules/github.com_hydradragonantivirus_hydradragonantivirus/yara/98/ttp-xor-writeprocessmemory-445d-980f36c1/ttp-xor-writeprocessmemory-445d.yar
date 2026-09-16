rule TTP_XOR_WriteProcessMemory_445d {
  strings:
    $key_445d = { 13 2f [2] 21 0d [2] 27 38 [2] 09 38 [2] 36 24 }

  condition:
    any of them
}