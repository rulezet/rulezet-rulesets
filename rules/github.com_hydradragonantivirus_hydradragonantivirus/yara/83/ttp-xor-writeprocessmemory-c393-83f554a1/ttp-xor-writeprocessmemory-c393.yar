rule TTP_XOR_WriteProcessMemory_c393 {
  strings:
    $key_c393 = { 94 e1 [2] a6 c3 [2] a0 f6 [2] 8e f6 [2] b1 ea }

  condition:
    any of them
}