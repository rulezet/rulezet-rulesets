rule TTP_XOR_WriteProcessMemory_c331 {
  strings:
    $key_c331 = { 94 43 [2] a6 61 [2] a0 54 [2] 8e 54 [2] b1 48 }

  condition:
    any of them
}