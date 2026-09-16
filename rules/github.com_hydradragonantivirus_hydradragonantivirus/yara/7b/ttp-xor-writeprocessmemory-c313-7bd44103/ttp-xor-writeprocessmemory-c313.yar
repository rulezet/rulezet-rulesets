rule TTP_XOR_WriteProcessMemory_c313 {
  strings:
    $key_c313 = { 94 61 [2] a6 43 [2] a0 76 [2] 8e 76 [2] b1 6a }

  condition:
    any of them
}