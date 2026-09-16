rule TTP_XOR_QUAD_CurrentVersionRun_ced2 {
  strings:
    $key_ced2 = { 9d bd [2] b9 b3 [2] 92 9f [2] bc bd [2] a8 a6 [2] a7 bc [2] b9 a1 [2] bb a0 [2] a0 a6 [2] bc a1 [2] a0 8e }

  condition:
    any of them
}