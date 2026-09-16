rule TTP_XOR_WriteProcessMemory_d792 {
  strings:
    $key_d792 = { 80 e0 [2] b2 c2 [2] b4 f7 [2] 9a f7 [2] a5 eb }

  condition:
    any of them
}