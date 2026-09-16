rule TTP_XOR_WriteProcessMemory_c787 {
  strings:
    $key_c787 = { 90 f5 [2] a2 d7 [2] a4 e2 [2] 8a e2 [2] b5 fe }

  condition:
    any of them
}