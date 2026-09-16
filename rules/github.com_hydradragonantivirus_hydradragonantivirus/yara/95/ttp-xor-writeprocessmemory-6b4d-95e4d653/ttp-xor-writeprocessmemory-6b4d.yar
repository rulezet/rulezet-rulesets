rule TTP_XOR_WriteProcessMemory_6b4d {
  strings:
    $key_6b4d = { 3c 3f [2] 0e 1d [2] 08 28 [2] 26 28 [2] 19 34 }

  condition:
    any of them
}