rule TTP_XOR_WriteProcessMemory_3744 {
  strings:
    $key_3744 = { 60 36 [2] 52 14 [2] 54 21 [2] 7a 21 [2] 45 3d }

  condition:
    any of them
}