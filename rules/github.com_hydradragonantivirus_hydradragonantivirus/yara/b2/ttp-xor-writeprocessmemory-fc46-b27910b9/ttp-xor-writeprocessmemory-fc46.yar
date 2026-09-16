rule TTP_XOR_WriteProcessMemory_fc46 {
  strings:
    $key_fc46 = { ab 34 [2] 99 16 [2] 9f 23 [2] b1 23 [2] 8e 3f }

  condition:
    any of them
}