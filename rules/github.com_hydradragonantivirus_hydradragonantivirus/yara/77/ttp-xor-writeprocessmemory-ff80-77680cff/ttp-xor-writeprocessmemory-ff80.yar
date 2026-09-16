rule TTP_XOR_WriteProcessMemory_ff80 {
  strings:
    $key_ff80 = { a8 f2 [2] 9a d0 [2] 9c e5 [2] b2 e5 [2] 8d f9 }

  condition:
    any of them
}