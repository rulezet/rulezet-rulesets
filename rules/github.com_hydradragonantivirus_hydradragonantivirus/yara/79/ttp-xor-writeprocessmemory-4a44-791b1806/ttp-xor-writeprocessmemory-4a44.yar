rule TTP_XOR_WriteProcessMemory_4a44 {
  strings:
    $key_4a44 = { 1d 36 [2] 2f 14 [2] 29 21 [2] 07 21 [2] 38 3d }

  condition:
    any of them
}