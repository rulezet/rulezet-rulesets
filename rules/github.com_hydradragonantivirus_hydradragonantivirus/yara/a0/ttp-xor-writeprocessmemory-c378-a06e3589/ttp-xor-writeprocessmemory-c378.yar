rule TTP_XOR_WriteProcessMemory_c378 {
  strings:
    $key_c378 = { 94 0a [2] a6 28 [2] a0 1d [2] 8e 1d [2] b1 01 }

  condition:
    any of them
}