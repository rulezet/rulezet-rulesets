rule TTP_XOR_WriteProcessMemory_d592 {
  strings:
    $key_d592 = { 82 e0 [2] b0 c2 [2] b6 f7 [2] 98 f7 [2] a7 eb }

  condition:
    any of them
}