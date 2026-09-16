rule TTP_XOR_WriteProcessMemory_c385 {
  strings:
    $key_c385 = { 94 f7 [2] a6 d5 [2] a0 e0 [2] 8e e0 [2] b1 fc }

  condition:
    any of them
}