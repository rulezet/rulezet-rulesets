rule TTP_XOR_WriteProcessMemory_fc48 {
  strings:
    $key_fc48 = { ab 3a [2] 99 18 [2] 9f 2d [2] b1 2d [2] 8e 31 }

  condition:
    any of them
}