rule TTP_XOR_WriteProcessMemory_075d {
  strings:
    $key_075d = { 50 2f [2] 62 0d [2] 64 38 [2] 4a 38 [2] 75 24 }

  condition:
    any of them
}