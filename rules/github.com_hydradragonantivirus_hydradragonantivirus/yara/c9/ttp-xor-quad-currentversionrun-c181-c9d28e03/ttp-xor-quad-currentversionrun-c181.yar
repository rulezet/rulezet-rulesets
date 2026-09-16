rule TTP_XOR_QUAD_CurrentVersionRun_c181 {
  strings:
    $key_c181 = { 92 ee [2] b6 e0 [2] 9d cc [2] b3 ee [2] a7 f5 [2] a8 ef [2] b6 f2 [2] b4 f3 [2] af f5 [2] b3 f2 [2] af dd }

  condition:
    any of them
}