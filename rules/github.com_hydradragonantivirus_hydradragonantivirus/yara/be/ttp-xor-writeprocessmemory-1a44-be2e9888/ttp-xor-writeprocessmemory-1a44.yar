rule TTP_XOR_WriteProcessMemory_1a44 {
  strings:
    $key_1a44 = { 4d 36 [2] 7f 14 [2] 79 21 [2] 57 21 [2] 68 3d }

  condition:
    any of them
}