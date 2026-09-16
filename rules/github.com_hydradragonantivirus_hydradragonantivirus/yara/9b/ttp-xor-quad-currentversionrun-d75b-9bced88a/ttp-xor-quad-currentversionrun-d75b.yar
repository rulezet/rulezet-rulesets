rule TTP_XOR_QUAD_CurrentVersionRun_d75b {
  strings:
    $key_d75b = { 84 34 [2] a0 3a [2] 8b 16 [2] a5 34 [2] b1 2f [2] be 35 [2] a0 28 [2] a2 29 [2] b9 2f [2] a5 28 [2] b9 07 }

  condition:
    any of them
}