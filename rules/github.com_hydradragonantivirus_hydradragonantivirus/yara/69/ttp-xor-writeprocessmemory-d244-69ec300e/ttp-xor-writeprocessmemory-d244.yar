rule TTP_XOR_WriteProcessMemory_d244 {
  strings:
    $key_d244 = { 85 36 [2] b7 14 [2] b1 21 [2] 9f 21 [2] a0 3d }

  condition:
    any of them
}