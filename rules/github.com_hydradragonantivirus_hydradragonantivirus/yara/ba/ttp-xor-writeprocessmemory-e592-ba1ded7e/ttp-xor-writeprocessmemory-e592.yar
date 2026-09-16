rule TTP_XOR_WriteProcessMemory_e592 {
  strings:
    $key_e592 = { b2 e0 [2] 80 c2 [2] 86 f7 [2] a8 f7 [2] 97 eb }

  condition:
    any of them
}