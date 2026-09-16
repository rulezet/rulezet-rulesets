rule TTP_XOR_WriteProcessMemory_d49c {
  strings:
    $key_d49c = { 83 ee [2] b1 cc [2] b7 f9 [2] 99 f9 [2] a6 e5 }

  condition:
    any of them
}