rule TTP_XOR_QUAD_CurrentVersionRun_cdf4 {
  strings:
    $key_cdf4 = { 9e 9b [2] ba 95 [2] 91 b9 [2] bf 9b [2] ab 80 [2] a4 9a [2] ba 87 [2] b8 86 [2] a3 80 [2] bf 87 [2] a3 a8 }

  condition:
    any of them
}