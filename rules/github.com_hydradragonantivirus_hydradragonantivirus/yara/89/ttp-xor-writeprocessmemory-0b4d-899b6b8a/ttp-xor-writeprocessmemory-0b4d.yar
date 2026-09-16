rule TTP_XOR_WriteProcessMemory_0b4d {
  strings:
    $key_0b4d = { 5c 3f [2] 6e 1d [2] 68 28 [2] 46 28 [2] 79 34 }

  condition:
    any of them
}