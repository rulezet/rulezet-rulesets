rule TTP_XOR_WriteProcessMemory_2f4d {
  strings:
    $key_2f4d = { 78 3f [2] 4a 1d [2] 4c 28 [2] 62 28 [2] 5d 34 }

  condition:
    any of them
}