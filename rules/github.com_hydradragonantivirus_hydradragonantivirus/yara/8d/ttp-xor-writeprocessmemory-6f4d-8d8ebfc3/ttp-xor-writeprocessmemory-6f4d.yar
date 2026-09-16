rule TTP_XOR_WriteProcessMemory_6f4d {
  strings:
    $key_6f4d = { 38 3f [2] 0a 1d [2] 0c 28 [2] 22 28 [2] 1d 34 }

  condition:
    any of them
}