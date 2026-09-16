rule TTP_XOR_WriteProcessMemory_6010 {
  strings:
    $key_6010 = { 37 62 [2] 05 40 [2] 03 75 [2] 2d 75 [2] 12 69 }

  condition:
    any of them
}