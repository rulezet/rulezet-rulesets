rule TTP_XOR_WriteProcessMemory_c794 {
  strings:
    $key_c794 = { 90 e6 [2] a2 c4 [2] a4 f1 [2] 8a f1 [2] b5 ed }

  condition:
    any of them
}