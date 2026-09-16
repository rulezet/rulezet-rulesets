rule TTP_XOR_WriteProcessMemory_caa0 {
  strings:
    $key_caa0 = { 9d d2 [2] af f0 [2] a9 c5 [2] 87 c5 [2] b8 d9 }

  condition:
    any of them
}