rule TTP_XOR_QUAD_CurrentVersionRun_d7d2 {
  strings:
    $key_d7d2 = { 84 bd [2] a0 b3 [2] 8b 9f [2] a5 bd [2] b1 a6 [2] be bc [2] a0 a1 [2] a2 a0 [2] b9 a6 [2] a5 a1 [2] b9 8e }

  condition:
    any of them
}