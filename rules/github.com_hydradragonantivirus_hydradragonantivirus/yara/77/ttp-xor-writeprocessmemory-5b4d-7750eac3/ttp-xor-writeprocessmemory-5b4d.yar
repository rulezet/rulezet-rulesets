rule TTP_XOR_WriteProcessMemory_5b4d {
  strings:
    $key_5b4d = { 0c 3f [2] 3e 1d [2] 38 28 [2] 16 28 [2] 29 34 }

  condition:
    any of them
}