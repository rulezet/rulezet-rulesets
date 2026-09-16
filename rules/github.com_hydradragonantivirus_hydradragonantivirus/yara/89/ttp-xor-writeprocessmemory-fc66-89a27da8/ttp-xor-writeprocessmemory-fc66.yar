rule TTP_XOR_WriteProcessMemory_fc66 {
  strings:
    $key_fc66 = { ab 14 [2] 99 36 [2] 9f 03 [2] b1 03 [2] 8e 1f }

  condition:
    any of them
}