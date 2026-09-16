rule TTP_XOR_QUAD_CurrentVersionRun_d190 {
  strings:
    $key_d190 = { 82 ff [2] a6 f1 [2] 8d dd [2] a3 ff [2] b7 e4 [2] b8 fe [2] a6 e3 [2] a4 e2 [2] bf e4 [2] a3 e3 [2] bf cc }

  condition:
    any of them
}