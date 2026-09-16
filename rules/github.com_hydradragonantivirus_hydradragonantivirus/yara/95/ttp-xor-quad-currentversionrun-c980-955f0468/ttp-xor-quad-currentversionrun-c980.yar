rule TTP_XOR_QUAD_CurrentVersionRun_c980 {
  strings:
    $key_c980 = { 9a ef [2] be e1 [2] 95 cd [2] bb ef [2] af f4 [2] a0 ee [2] be f3 [2] bc f2 [2] a7 f4 [2] bb f3 [2] a7 dc }

  condition:
    any of them
}