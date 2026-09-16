rule TTP_XOR_WriteProcessMemory_fa84 {
  strings:
    $key_fa84 = { ad f6 [2] 9f d4 [2] 99 e1 [2] b7 e1 [2] 88 fd }

  condition:
    any of them
}