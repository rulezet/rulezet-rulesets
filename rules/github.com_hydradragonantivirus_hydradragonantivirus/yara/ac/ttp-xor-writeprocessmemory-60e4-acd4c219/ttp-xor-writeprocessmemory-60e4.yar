rule TTP_XOR_WriteProcessMemory_60e4 {
  strings:
    $key_60e4 = { 37 96 [2] 05 b4 [2] 03 81 [2] 2d 81 [2] 12 9d }

  condition:
    any of them
}