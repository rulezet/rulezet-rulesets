rule TTP_XOR_WriteProcessMemory_fc43 {
  strings:
    $key_fc43 = { ab 31 [2] 99 13 [2] 9f 26 [2] b1 26 [2] 8e 3a }

  condition:
    any of them
}