rule TTP_XOR_WriteProcessMemory_d794 {
  strings:
    $key_d794 = { 80 e6 [2] b2 c4 [2] b4 f1 [2] 9a f1 [2] a5 ed }

  condition:
    any of them
}