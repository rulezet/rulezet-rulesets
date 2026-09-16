rule TTP_XOR_WriteProcessMemory_d744 {
  strings:
    $key_d744 = { 80 36 [2] b2 14 [2] b4 21 [2] 9a 21 [2] a5 3d }

  condition:
    any of them
}