rule TTP_XOR_WriteProcessMemory_fc76 {
  strings:
    $key_fc76 = { ab 04 [2] 99 26 [2] 9f 13 [2] b1 13 [2] 8e 0f }

  condition:
    any of them
}