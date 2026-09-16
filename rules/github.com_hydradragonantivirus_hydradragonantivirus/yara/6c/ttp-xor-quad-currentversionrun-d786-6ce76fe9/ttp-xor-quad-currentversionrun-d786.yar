rule TTP_XOR_QUAD_CurrentVersionRun_d786 {
  strings:
    $key_d786 = { 84 e9 [2] a0 e7 [2] 8b cb [2] a5 e9 [2] b1 f2 [2] be e8 [2] a0 f5 [2] a2 f4 [2] b9 f2 [2] a5 f5 [2] b9 da }

  condition:
    any of them
}