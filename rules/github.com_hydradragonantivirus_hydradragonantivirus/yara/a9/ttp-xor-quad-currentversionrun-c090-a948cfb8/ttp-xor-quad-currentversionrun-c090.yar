rule TTP_XOR_QUAD_CurrentVersionRun_c090 {
  strings:
    $key_c090 = { 93 ff [2] b7 f1 [2] 9c dd [2] b2 ff [2] a6 e4 [2] a9 fe [2] b7 e3 [2] b5 e2 [2] ae e4 [2] b2 e3 [2] ae cc }

  condition:
    any of them
}