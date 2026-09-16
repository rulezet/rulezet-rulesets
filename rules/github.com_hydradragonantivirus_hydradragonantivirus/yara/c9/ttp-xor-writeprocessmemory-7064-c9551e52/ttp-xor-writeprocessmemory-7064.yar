rule TTP_XOR_WriteProcessMemory_7064 {
  strings:
    $key_7064 = { 27 16 [2] 15 34 [2] 13 01 [2] 3d 01 [2] 02 1d }

  condition:
    any of them
}