rule TTP_XOR_WriteProcessMemory_c265 {
  strings:
    $key_c265 = { 95 17 [2] a7 35 [2] a1 00 [2] 8f 00 [2] b0 1c }

  condition:
    any of them
}