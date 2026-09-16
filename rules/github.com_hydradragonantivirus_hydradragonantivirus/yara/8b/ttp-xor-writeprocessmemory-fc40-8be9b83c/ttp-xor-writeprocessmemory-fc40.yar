rule TTP_XOR_WriteProcessMemory_fc40 {
  strings:
    $key_fc40 = { ab 32 [2] 99 10 [2] 9f 25 [2] b1 25 [2] 8e 39 }

  condition:
    any of them
}