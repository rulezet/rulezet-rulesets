rule TTP_XOR_WriteProcessMemory_631d {
  strings:
    $key_631d = { 34 6f [2] 06 4d [2] 00 78 [2] 2e 78 [2] 11 64 }

  condition:
    any of them
}