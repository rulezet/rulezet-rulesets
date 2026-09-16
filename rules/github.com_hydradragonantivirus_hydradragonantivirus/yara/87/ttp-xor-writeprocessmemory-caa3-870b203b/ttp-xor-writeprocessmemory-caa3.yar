rule TTP_XOR_WriteProcessMemory_caa3 {
  strings:
    $key_caa3 = { 9d d1 [2] af f3 [2] a9 c6 [2] 87 c6 [2] b8 da }

  condition:
    any of them
}