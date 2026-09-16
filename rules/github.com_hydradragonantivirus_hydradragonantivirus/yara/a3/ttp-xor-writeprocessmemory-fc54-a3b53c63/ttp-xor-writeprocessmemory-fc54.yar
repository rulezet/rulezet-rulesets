rule TTP_XOR_WriteProcessMemory_fc54 {
  strings:
    $key_fc54 = { ab 26 [2] 99 04 [2] 9f 31 [2] b1 31 [2] 8e 2d }

  condition:
    any of them
}