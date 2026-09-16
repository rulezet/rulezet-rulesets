rule TTP_XOR_WriteProcessMemory_ff94 {
  strings:
    $key_ff94 = { a8 e6 [2] 9a c4 [2] 9c f1 [2] b2 f1 [2] 8d ed }

  condition:
    any of them
}