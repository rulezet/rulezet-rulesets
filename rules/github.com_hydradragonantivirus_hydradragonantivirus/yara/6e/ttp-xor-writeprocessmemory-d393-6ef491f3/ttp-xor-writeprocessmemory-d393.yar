rule TTP_XOR_WriteProcessMemory_d393 {
  strings:
    $key_d393 = { 84 e1 [2] b6 c3 [2] b0 f6 [2] 9e f6 [2] a1 ea }

  condition:
    any of them
}