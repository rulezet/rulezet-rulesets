rule TTP_XOR_WriteProcessMemory_d253 {
  strings:
    $key_d253 = { 85 21 [2] b7 03 [2] b1 36 [2] 9f 36 [2] a0 2a }

  condition:
    any of them
}