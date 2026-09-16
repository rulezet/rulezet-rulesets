rule TTP_XOR_WriteProcessMemory_60ce {
  strings:
    $key_60ce = { 37 bc [2] 05 9e [2] 03 ab [2] 2d ab [2] 12 b7 }

  condition:
    any of them
}