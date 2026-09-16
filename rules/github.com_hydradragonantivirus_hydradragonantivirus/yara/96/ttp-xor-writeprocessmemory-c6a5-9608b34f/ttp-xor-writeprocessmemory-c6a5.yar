rule TTP_XOR_WriteProcessMemory_c6a5 {
  strings:
    $key_c6a5 = { 91 d7 [2] a3 f5 [2] a5 c0 [2] 8b c0 [2] b4 dc }

  condition:
    any of them
}