rule TTP_XOR_WriteProcessMemory_c382 {
  strings:
    $key_c382 = { 94 f0 [2] a6 d2 [2] a0 e7 [2] 8e e7 [2] b1 fb }

  condition:
    any of them
}