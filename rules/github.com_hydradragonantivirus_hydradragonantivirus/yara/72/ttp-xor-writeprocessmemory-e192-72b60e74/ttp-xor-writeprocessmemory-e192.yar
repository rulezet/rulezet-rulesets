rule TTP_XOR_WriteProcessMemory_e192 {
  strings:
    $key_e192 = { b6 e0 [2] 84 c2 [2] 82 f7 [2] ac f7 [2] 93 eb }

  condition:
    any of them
}