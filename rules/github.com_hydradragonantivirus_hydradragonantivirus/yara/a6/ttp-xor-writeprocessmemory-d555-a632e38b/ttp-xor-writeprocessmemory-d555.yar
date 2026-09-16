rule TTP_XOR_WriteProcessMemory_d555 {
  strings:
    $key_d555 = { 82 27 [2] b0 05 [2] b6 30 [2] 98 30 [2] a7 2c }

  condition:
    any of them
}