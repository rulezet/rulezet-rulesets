rule TTP_XOR_QUAD_CurrentVersionRun_cea6 {
  strings:
    $key_cea6 = { 9d c9 [2] b9 c7 [2] 92 eb [2] bc c9 [2] a8 d2 [2] a7 c8 [2] b9 d5 [2] bb d4 [2] a0 d2 [2] bc d5 [2] a0 fa }

  condition:
    any of them
}