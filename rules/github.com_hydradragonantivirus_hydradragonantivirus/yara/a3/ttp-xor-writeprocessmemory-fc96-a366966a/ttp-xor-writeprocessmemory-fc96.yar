rule TTP_XOR_WriteProcessMemory_fc96 {
  strings:
    $key_fc96 = { ab e4 [2] 99 c6 [2] 9f f3 [2] b1 f3 [2] 8e ef }

  condition:
    any of them
}