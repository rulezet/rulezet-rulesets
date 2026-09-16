rule TTP_XOR_WriteProcessMemory_5d4d {
  strings:
    $key_5d4d = { 0a 3f [2] 38 1d [2] 3e 28 [2] 10 28 [2] 2f 34 }

  condition:
    any of them
}