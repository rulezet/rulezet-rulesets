rule TTP_XOR_WriteProcessMemory_c192 {
  strings:
    $key_c192 = { 96 e0 [2] a4 c2 [2] a2 f7 [2] 8c f7 [2] b3 eb }

  condition:
    any of them
}