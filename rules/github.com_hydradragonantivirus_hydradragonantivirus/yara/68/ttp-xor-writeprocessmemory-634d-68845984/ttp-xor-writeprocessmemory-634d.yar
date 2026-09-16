rule TTP_XOR_WriteProcessMemory_634d {
  strings:
    $key_634d = { 34 3f [2] 06 1d [2] 00 28 [2] 2e 28 [2] 11 34 }

  condition:
    any of them
}