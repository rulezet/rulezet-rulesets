rule TTP_XOR_WriteProcessMemory_5d1d {
  strings:
    $key_5d1d = { 0a 6f [2] 38 4d [2] 3e 78 [2] 10 78 [2] 2f 64 }

  condition:
    any of them
}