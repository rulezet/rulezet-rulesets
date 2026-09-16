rule TTP_XOR_WriteProcessMemory_3185 {
  strings:
    $key_3185 = { 66 f7 [2] 54 d5 [2] 52 e0 [2] 7c e0 [2] 43 fc }

  condition:
    any of them
}