rule TTP_XOR_WriteProcessMemory_553d {
  strings:
    $key_553d = { 02 4f [2] 30 6d [2] 36 58 [2] 18 58 [2] 27 44 }

  condition:
    any of them
}