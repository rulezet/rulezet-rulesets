rule TTP_XOR_WriteProcessMemory_7e4d {
  strings:
    $key_7e4d = { 29 3f [2] 1b 1d [2] 1d 28 [2] 33 28 [2] 0c 34 }

  condition:
    any of them
}