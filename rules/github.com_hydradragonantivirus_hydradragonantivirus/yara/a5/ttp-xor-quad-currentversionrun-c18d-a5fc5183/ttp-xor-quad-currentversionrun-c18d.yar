rule TTP_XOR_QUAD_CurrentVersionRun_c18d {
  strings:
    $key_c18d = { 92 e2 [2] b6 ec [2] 9d c0 [2] b3 e2 [2] a7 f9 [2] a8 e3 [2] b6 fe [2] b4 ff [2] af f9 [2] b3 fe [2] af d1 }

  condition:
    any of them
}