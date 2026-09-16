rule TTP_XOR_WriteProcessMemory_fc26 {
  strings:
    $key_fc26 = { ab 54 [2] 99 76 [2] 9f 43 [2] b1 43 [2] 8e 5f }

  condition:
    any of them
}