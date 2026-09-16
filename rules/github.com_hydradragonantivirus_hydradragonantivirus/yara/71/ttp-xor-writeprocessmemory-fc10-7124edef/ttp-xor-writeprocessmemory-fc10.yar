rule TTP_XOR_WriteProcessMemory_fc10 {
  strings:
    $key_fc10 = { ab 62 [2] 99 40 [2] 9f 75 [2] b1 75 [2] 8e 69 }

  condition:
    any of them
}