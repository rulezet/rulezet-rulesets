rule TTP_XOR_WriteProcessMemory_5c1d {
  strings:
    $key_5c1d = { 0b 6f [2] 39 4d [2] 3f 78 [2] 11 78 [2] 2e 64 }

  condition:
    any of them
}