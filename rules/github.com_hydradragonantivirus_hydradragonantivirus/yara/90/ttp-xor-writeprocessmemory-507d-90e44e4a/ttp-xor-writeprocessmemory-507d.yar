rule TTP_XOR_WriteProcessMemory_507d {
  strings:
    $key_507d = { 07 0f [2] 35 2d [2] 33 18 [2] 1d 18 [2] 22 04 }

  condition:
    any of them
}