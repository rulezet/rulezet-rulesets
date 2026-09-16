rule TTP_XOR_WriteProcessMemory_c367 {
  strings:
    $key_c367 = { 94 15 [2] a6 37 [2] a0 02 [2] 8e 02 [2] b1 1e }

  condition:
    any of them
}