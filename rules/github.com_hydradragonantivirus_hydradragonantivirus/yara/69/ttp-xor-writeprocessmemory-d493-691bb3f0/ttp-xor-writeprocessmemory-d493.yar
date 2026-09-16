rule TTP_XOR_WriteProcessMemory_d493 {
  strings:
    $key_d493 = { 83 e1 [2] b1 c3 [2] b7 f6 [2] 99 f6 [2] a6 ea }

  condition:
    any of them
}