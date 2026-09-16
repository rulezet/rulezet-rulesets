rule TTP_XOR_WriteProcessMemory_fa80 {
  strings:
    $key_fa80 = { ad f2 [2] 9f d0 [2] 99 e5 [2] b7 e5 [2] 88 f9 }

  condition:
    any of them
}