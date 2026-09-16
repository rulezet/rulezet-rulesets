rule TTP_XOR_WriteProcessMemory_fc16 {
  strings:
    $key_fc16 = { ab 64 [2] 99 46 [2] 9f 73 [2] b1 73 [2] 8e 6f }

  condition:
    any of them
}