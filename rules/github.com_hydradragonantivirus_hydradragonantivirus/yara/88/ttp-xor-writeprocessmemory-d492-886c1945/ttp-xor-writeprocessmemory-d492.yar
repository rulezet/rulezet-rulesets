rule TTP_XOR_WriteProcessMemory_d492 {
  strings:
    $key_d492 = { 83 e0 [2] b1 c2 [2] b7 f7 [2] 99 f7 [2] a6 eb }

  condition:
    any of them
}