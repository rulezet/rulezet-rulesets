rule TTP_XOR_QUAD_CurrentVersionRun_cbcf {
  strings:
    $key_cbcf = { 98 a0 [2] bc ae [2] 97 82 [2] b9 a0 [2] ad bb [2] a2 a1 [2] bc bc [2] be bd [2] a5 bb [2] b9 bc [2] a5 93 }

  condition:
    any of them
}