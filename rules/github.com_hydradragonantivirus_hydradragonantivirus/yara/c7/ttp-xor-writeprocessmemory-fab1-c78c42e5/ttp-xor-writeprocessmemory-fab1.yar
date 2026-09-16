rule TTP_XOR_WriteProcessMemory_fab1 {
  strings:
    $key_fab1 = { ad c3 [2] 9f e1 [2] 99 d4 [2] b7 d4 [2] 88 c8 }

  condition:
    any of them
}