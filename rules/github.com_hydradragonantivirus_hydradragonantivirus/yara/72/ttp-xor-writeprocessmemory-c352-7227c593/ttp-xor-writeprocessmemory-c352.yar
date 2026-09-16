rule TTP_XOR_WriteProcessMemory_c352 {
  strings:
    $key_c352 = { 94 20 [2] a6 02 [2] a0 37 [2] 8e 37 [2] b1 2b }

  condition:
    any of them
}