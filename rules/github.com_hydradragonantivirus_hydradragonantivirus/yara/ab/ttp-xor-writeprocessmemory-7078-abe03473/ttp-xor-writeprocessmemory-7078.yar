rule TTP_XOR_WriteProcessMemory_7078 {
  strings:
    $key_7078 = { 27 0a [2] 15 28 [2] 13 1d [2] 3d 1d [2] 02 01 }

  condition:
    any of them
}