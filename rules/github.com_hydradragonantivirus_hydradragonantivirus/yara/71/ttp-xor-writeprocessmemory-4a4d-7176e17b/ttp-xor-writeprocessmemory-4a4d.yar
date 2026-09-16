rule TTP_XOR_WriteProcessMemory_4a4d {
  strings:
    $key_4a4d = { 1d 3f [2] 2f 1d [2] 29 28 [2] 07 28 [2] 38 34 }

  condition:
    any of them
}