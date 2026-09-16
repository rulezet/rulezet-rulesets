rule TTP_XOR_WriteProcessMemory_3192 {
  strings:
    $key_3192 = { 66 e0 [2] 54 c2 [2] 52 f7 [2] 7c f7 [2] 43 eb }

  condition:
    any of them
}