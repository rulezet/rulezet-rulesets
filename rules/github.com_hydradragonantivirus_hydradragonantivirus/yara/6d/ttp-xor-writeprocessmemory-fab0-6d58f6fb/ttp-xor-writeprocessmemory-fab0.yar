rule TTP_XOR_WriteProcessMemory_fab0 {
  strings:
    $key_fab0 = { ad c2 [2] 9f e0 [2] 99 d5 [2] b7 d5 [2] 88 c9 }

  condition:
    any of them
}