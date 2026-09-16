rule TTP_XOR_WriteProcessMemory_caa4 {
  strings:
    $key_caa4 = { 9d d6 [2] af f4 [2] a9 c1 [2] 87 c1 [2] b8 dd }

  condition:
    any of them
}