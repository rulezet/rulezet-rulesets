rule TTP_XOR_WriteProcessMemory_1044 {
  strings:
    $key_1044 = { 47 36 [2] 75 14 [2] 73 21 [2] 5d 21 [2] 62 3d }

  condition:
    any of them
}