rule TTP_XOR_WriteProcessMemory_6064 {
  strings:
    $key_6064 = { 37 16 [2] 05 34 [2] 03 01 [2] 2d 01 [2] 12 1d }

  condition:
    any of them
}