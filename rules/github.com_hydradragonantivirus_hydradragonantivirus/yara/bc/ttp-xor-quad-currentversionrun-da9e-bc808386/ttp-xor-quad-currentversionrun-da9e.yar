rule TTP_XOR_QUAD_CurrentVersionRun_da9e {
  strings:
    $key_da9e = { 89 f1 [2] ad ff [2] 86 d3 [2] a8 f1 [2] bc ea [2] b3 f0 [2] ad ed [2] af ec [2] b4 ea [2] a8 ed [2] b4 c2 }

  condition:
    any of them
}