rule TTP_XOR_WriteProcessMemory_6041 {
  strings:
    $key_6041 = { 37 33 [2] 05 11 [2] 03 24 [2] 2d 24 [2] 12 38 }

  condition:
    any of them
}