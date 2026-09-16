rule TTP_XOR_QUAD_CurrentVersionRun_c3c0 {
  strings:
    $key_c3c0 = { 90 af [2] b4 a1 [2] 9f 8d [2] b1 af [2] a5 b4 [2] aa ae [2] b4 b3 [2] b6 b2 [2] ad b4 [2] b1 b3 [2] ad 9c }

  condition:
    any of them
}