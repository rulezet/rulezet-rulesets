rule TTP_XOR_WriteProcessMemory_fc70 {
  strings:
    $key_fc70 = { ab 02 [2] 99 20 [2] 9f 15 [2] b1 15 [2] 8e 09 }

  condition:
    any of them
}