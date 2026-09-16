rule TTP_XOR_WriteProcessMemory_343d {
  strings:
    $key_343d = { 63 4f [2] 51 6d [2] 57 58 [2] 79 58 [2] 46 44 }

  condition:
    any of them
}