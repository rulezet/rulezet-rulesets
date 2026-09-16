rule TTP_XOR_QUAD_CurrentVersionRun_cdf1 {
  strings:
    $key_cdf1 = { 9e 9e [2] ba 90 [2] 91 bc [2] bf 9e [2] ab 85 [2] a4 9f [2] ba 82 [2] b8 83 [2] a3 85 [2] bf 82 [2] a3 ad }

  condition:
    any of them
}