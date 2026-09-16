rule TTP_XOR_WriteProcessMemory_1d5d {
  strings:
    $key_1d5d = { 4a 2f [2] 78 0d [2] 7e 38 [2] 50 38 [2] 6f 24 }

  condition:
    any of them
}