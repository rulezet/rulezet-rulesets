rule TTP_XOR_WriteProcessMemory_6016 {
  strings:
    $key_6016 = { 37 64 [2] 05 46 [2] 03 73 [2] 2d 73 [2] 12 6f }

  condition:
    any of them
}