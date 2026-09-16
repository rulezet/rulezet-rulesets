rule TTP_XOR_WriteProcessMemory_caa6 {
  strings:
    $key_caa6 = { 9d d4 [2] af f6 [2] a9 c3 [2] 87 c3 [2] b8 df }

  condition:
    any of them
}