rule TTP_XOR_QUAD_CurrentVersionRun_dfdc {
  strings:
    $key_dfdc = { 8c b3 [2] a8 bd [2] 83 91 [2] ad b3 [2] b9 a8 [2] b6 b2 [2] a8 af [2] aa ae [2] b1 a8 [2] ad af [2] b1 80 }

  condition:
    any of them
}