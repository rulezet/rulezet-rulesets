rule TTP_XOR_WriteProcessMemory_6022 {
  strings:
    $key_6022 = { 37 50 [2] 05 72 [2] 03 47 [2] 2d 47 [2] 12 5b }

  condition:
    any of them
}