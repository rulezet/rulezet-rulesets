rule TTP_XOR_QUAD_CurrentVersionRun_c790 {
  strings:
    $key_c790 = { 94 ff [2] b0 f1 [2] 9b dd [2] b5 ff [2] a1 e4 [2] ae fe [2] b0 e3 [2] b2 e2 [2] a9 e4 [2] b5 e3 [2] a9 cc }

  condition:
    any of them
}