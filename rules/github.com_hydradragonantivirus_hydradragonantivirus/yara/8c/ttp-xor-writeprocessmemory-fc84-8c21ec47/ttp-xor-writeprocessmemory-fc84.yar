rule TTP_XOR_WriteProcessMemory_fc84 {
  strings:
    $key_fc84 = { ab f6 [2] 99 d4 [2] 9f e1 [2] b1 e1 [2] 8e fd }

  condition:
    any of them
}