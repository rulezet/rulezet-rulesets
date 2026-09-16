rule TTP_XOR_WriteProcessMemory_fc44 {
  strings:
    $key_fc44 = { ab 36 [2] 99 14 [2] 9f 21 [2] b1 21 [2] 8e 3d }

  condition:
    any of them
}