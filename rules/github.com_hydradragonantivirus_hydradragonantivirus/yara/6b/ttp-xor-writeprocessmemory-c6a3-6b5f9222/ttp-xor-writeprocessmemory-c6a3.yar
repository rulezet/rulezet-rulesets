rule TTP_XOR_WriteProcessMemory_c6a3 {
  strings:
    $key_c6a3 = { 91 d1 [2] a3 f3 [2] a5 c6 [2] 8b c6 [2] b4 da }

  condition:
    any of them
}