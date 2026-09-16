rule TTP_XOR_WriteProcessMemory_4e44 {
  strings:
    $key_4e44 = { 19 36 [2] 2b 14 [2] 2d 21 [2] 03 21 [2] 3c 3d }

  condition:
    any of them
}