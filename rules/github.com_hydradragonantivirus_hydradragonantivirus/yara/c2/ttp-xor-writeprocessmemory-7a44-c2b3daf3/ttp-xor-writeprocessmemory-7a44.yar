rule TTP_XOR_WriteProcessMemory_7a44 {
  strings:
    $key_7a44 = { 2d 36 [2] 1f 14 [2] 19 21 [2] 37 21 [2] 08 3d }

  condition:
    any of them
}