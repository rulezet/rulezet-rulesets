rule TTP_XOR_QUAD_CurrentVersionRun_c496 {
  strings:
    $key_c496 = { 97 f9 [2] b3 f7 [2] 98 db [2] b6 f9 [2] a2 e2 [2] ad f8 [2] b3 e5 [2] b1 e4 [2] aa e2 [2] b6 e5 [2] aa ca }

  condition:
    any of them
}