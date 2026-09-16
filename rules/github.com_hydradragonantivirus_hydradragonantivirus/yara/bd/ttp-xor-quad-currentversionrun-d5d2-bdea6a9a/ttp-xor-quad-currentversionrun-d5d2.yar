rule TTP_XOR_QUAD_CurrentVersionRun_d5d2 {
  strings:
    $key_d5d2 = { 86 bd [2] a2 b3 [2] 89 9f [2] a7 bd [2] b3 a6 [2] bc bc [2] a2 a1 [2] a0 a0 [2] bb a6 [2] a7 a1 [2] bb 8e }

  condition:
    any of them
}