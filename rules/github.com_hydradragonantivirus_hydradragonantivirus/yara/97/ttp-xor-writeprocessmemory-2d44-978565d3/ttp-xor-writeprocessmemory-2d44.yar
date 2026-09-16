rule TTP_XOR_WriteProcessMemory_2d44 {
  strings:
    $key_2d44 = { 7a 36 [2] 48 14 [2] 4e 21 [2] 60 21 [2] 5f 3d }

  condition:
    any of them
}