rule TTP_XOR_QUAD_CurrentVersionRun_da8c {
  strings:
    $key_da8c = { 89 e3 [2] ad ed [2] 86 c1 [2] a8 e3 [2] bc f8 [2] b3 e2 [2] ad ff [2] af fe [2] b4 f8 [2] a8 ff [2] b4 d0 }

  condition:
    any of them
}