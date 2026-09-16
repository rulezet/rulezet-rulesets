rule TTP_XOR_WriteProcessMemory_d2b5 {
  strings:
    $key_d2b5 = { 85 c7 [2] b7 e5 [2] b1 d0 [2] 9f d0 [2] a0 cc }

  condition:
    any of them
}