rule TTP_XOR_WriteProcessMemory_6d4d {
  strings:
    $key_6d4d = { 3a 3f [2] 08 1d [2] 0e 28 [2] 20 28 [2] 1f 34 }

  condition:
    any of them
}