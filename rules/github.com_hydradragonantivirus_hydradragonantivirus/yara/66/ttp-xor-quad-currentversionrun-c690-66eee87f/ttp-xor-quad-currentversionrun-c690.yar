rule TTP_XOR_QUAD_CurrentVersionRun_c690 {
  strings:
    $key_c690 = { 95 ff [2] b1 f1 [2] 9a dd [2] b4 ff [2] a0 e4 [2] af fe [2] b1 e3 [2] b3 e2 [2] a8 e4 [2] b4 e3 [2] a8 cc }

  condition:
    any of them
}