rule TTP_XOR_WriteProcessMemory_3182 {
  strings:
    $key_3182 = { 66 f0 [2] 54 d2 [2] 52 e7 [2] 7c e7 [2] 43 fb }

  condition:
    any of them
}