rule TTP_XOR_QUAD_CurrentVersionRun_c99e {
  strings:
    $key_c99e = { 9a f1 [2] be ff [2] 95 d3 [2] bb f1 [2] af ea [2] a0 f0 [2] be ed [2] bc ec [2] a7 ea [2] bb ed [2] a7 c2 }

  condition:
    any of them
}