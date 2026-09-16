rule TTP_XOR_WriteProcessMemory_2d2d {
  strings:
    $key_2d2d = { 7a 5f [2] 48 7d [2] 4e 48 [2] 60 48 [2] 5f 54 }

  condition:
    any of them
}