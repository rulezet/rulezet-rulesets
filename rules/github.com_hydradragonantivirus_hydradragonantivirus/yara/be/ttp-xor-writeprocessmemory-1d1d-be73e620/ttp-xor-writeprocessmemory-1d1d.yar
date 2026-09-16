rule TTP_XOR_WriteProcessMemory_1d1d {
  strings:
    $key_1d1d = { 4a 6f [2] 78 4d [2] 7e 78 [2] 50 78 [2] 6f 64 }

  condition:
    any of them
}