rule TTP_XOR_WriteProcessMemory_d39c {
  strings:
    $key_d39c = { 84 ee [2] b6 cc [2] b0 f9 [2] 9e f9 [2] a1 e5 }

  condition:
    any of them
}