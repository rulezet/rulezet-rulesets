rule TTP_XOR_WriteProcessMemory_5f44 {
  strings:
    $key_5f44 = { 08 36 [2] 3a 14 [2] 3c 21 [2] 12 21 [2] 2d 3d }

  condition:
    any of them
}