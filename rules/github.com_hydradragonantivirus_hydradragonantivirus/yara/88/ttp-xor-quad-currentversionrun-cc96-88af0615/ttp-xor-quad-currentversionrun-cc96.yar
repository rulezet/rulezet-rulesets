rule TTP_XOR_QUAD_CurrentVersionRun_cc96 {
  strings:
    $key_cc96 = { 9f f9 [2] bb f7 [2] 90 db [2] be f9 [2] aa e2 [2] a5 f8 [2] bb e5 [2] b9 e4 [2] a2 e2 [2] be e5 [2] a2 ca }

  condition:
    any of them
}