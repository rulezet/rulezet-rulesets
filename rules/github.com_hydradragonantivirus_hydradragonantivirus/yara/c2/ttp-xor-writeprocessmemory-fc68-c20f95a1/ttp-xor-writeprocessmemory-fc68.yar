rule TTP_XOR_WriteProcessMemory_fc68 {
  strings:
    $key_fc68 = { ab 1a [2] 99 38 [2] 9f 0d [2] b1 0d [2] 8e 11 }

  condition:
    any of them
}