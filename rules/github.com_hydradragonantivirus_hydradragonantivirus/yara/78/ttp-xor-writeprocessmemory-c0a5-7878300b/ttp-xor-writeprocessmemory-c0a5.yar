rule TTP_XOR_WriteProcessMemory_c0a5 {
  strings:
    $key_c0a5 = { 97 d7 [2] a5 f5 [2] a3 c0 [2] 8d c0 [2] b2 dc }

  condition:
    any of them
}