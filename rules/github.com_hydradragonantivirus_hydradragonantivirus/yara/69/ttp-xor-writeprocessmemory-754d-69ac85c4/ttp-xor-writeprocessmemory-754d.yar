rule TTP_XOR_WriteProcessMemory_754d {
  strings:
    $key_754d = { 22 3f [2] 10 1d [2] 16 28 [2] 38 28 [2] 07 34 }

  condition:
    any of them
}