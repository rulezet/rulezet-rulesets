rule TTP_XOR_WriteProcessMemory_c744 {
  strings:
    $key_c744 = { 90 36 [2] a2 14 [2] a4 21 [2] 8a 21 [2] b5 3d }

  condition:
    any of them
}