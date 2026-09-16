rule TTP_XOR_WriteProcessMemory_c387 {
  strings:
    $key_c387 = { 94 f5 [2] a6 d7 [2] a0 e2 [2] 8e e2 [2] b1 fe }

  condition:
    any of them
}