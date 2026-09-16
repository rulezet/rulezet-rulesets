rule TTP_XOR_WriteProcessMemory_743d {
  strings:
    $key_743d = { 23 4f [2] 11 6d [2] 17 58 [2] 39 58 [2] 06 44 }

  condition:
    any of them
}