rule TTP_XOR_WriteProcessMemory_1c4d {
  strings:
    $key_1c4d = { 4b 3f [2] 79 1d [2] 7f 28 [2] 51 28 [2] 6e 34 }

  condition:
    any of them
}