rule TTP_XOR_QUAD_CurrentVersionRun_d6dd {
  strings:
    $key_d6dd = { 85 b2 [2] a1 bc [2] 8a 90 [2] a4 b2 [2] b0 a9 [2] bf b3 [2] a1 ae [2] a3 af [2] b8 a9 [2] a4 ae [2] b8 81 }

  condition:
    any of them
}