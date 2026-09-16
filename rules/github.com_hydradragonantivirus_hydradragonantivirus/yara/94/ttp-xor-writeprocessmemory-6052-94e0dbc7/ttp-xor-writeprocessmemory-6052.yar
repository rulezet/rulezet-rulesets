rule TTP_XOR_WriteProcessMemory_6052 {
  strings:
    $key_6052 = { 37 20 [2] 05 02 [2] 03 37 [2] 2d 37 [2] 12 2b }

  condition:
    any of them
}