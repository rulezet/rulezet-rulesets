rule TTP_XOR_WriteProcessMemory_6033 {
  strings:
    $key_6033 = { 37 41 [2] 05 63 [2] 03 56 [2] 2d 56 [2] 12 4a }

  condition:
    any of them
}