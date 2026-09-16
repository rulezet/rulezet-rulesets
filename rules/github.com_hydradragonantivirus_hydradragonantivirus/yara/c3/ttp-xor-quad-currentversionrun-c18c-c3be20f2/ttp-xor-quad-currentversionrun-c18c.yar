rule TTP_XOR_QUAD_CurrentVersionRun_c18c {
  strings:
    $key_c18c = { 92 e3 [2] b6 ed [2] 9d c1 [2] b3 e3 [2] a7 f8 [2] a8 e2 [2] b6 ff [2] b4 fe [2] af f8 [2] b3 ff [2] af d0 }

  condition:
    any of them
}