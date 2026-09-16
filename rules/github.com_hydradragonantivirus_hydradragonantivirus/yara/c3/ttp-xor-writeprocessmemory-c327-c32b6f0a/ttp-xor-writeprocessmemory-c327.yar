rule TTP_XOR_WriteProcessMemory_c327 {
  strings:
    $key_c327 = { 94 55 [2] a6 77 [2] a0 42 [2] 8e 42 [2] b1 5e }

  condition:
    any of them
}