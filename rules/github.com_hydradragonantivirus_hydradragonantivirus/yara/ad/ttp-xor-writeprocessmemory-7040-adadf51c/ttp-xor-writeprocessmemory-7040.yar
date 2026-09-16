rule TTP_XOR_WriteProcessMemory_7040 {
  strings:
    $key_7040 = { 27 32 [2] 15 10 [2] 13 25 [2] 3d 25 [2] 02 39 }

  condition:
    any of them
}