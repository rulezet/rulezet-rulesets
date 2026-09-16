rule TTP_XOR_WriteProcessMemory_e5a5 {
  strings:
    $key_e5a5 = { b2 d7 [2] 80 f5 [2] 86 c0 [2] a8 c0 [2] 97 dc }

  condition:
    any of them
}