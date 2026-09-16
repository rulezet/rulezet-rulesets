rule TTP_XOR_WriteProcessMemory_c292 {
  strings:
    $key_c292 = { 95 e0 [2] a7 c2 [2] a1 f7 [2] 8f f7 [2] b0 eb }

  condition:
    any of them
}