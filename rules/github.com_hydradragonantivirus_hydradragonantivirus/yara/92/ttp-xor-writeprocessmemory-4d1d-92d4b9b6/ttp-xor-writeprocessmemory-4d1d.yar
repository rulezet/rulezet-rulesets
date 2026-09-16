rule TTP_XOR_WriteProcessMemory_4d1d {
  strings:
    $key_4d1d = { 1a 6f [2] 28 4d [2] 2e 78 [2] 00 78 [2] 3f 64 }

  condition:
    any of them
}