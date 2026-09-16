rule TTP_XOR_WriteProcessMemory_d292 {
  strings:
    $key_d292 = { 85 e0 [2] b7 c2 [2] b1 f7 [2] 9f f7 [2] a0 eb }

  condition:
    any of them
}