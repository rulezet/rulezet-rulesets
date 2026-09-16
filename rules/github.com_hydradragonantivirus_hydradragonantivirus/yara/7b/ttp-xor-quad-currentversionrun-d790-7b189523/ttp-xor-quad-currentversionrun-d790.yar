rule TTP_XOR_QUAD_CurrentVersionRun_d790 {
  strings:
    $key_d790 = { 84 ff [2] a0 f1 [2] 8b dd [2] a5 ff [2] b1 e4 [2] be fe [2] a0 e3 [2] a2 e2 [2] b9 e4 [2] a5 e3 [2] b9 cc }

  condition:
    any of them
}