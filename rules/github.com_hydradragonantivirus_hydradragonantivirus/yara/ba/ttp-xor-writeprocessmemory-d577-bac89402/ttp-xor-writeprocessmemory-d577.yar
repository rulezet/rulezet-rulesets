rule TTP_XOR_WriteProcessMemory_d577 {
  strings:
    $key_d577 = { 82 05 [2] b0 27 [2] b6 12 [2] 98 12 [2] a7 0e }

  condition:
    any of them
}