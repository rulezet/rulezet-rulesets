rule TTP_XOR_WriteProcessMemory_fc13 {
  strings:
    $key_fc13 = { ab 61 [2] 99 43 [2] 9f 76 [2] b1 76 [2] 8e 6a }

  condition:
    any of them
}