rule TTP_XOR_WriteProcessMemory_d444 {
  strings:
    $key_d444 = { 83 36 [2] b1 14 [2] b7 21 [2] 99 21 [2] a6 3d }

  condition:
    any of them
}