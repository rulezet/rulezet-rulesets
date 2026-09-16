rule TTP_XOR_QUAD_CurrentVersionRun_cdf8 {
  strings:
    $key_cdf8 = { 9e 97 [2] ba 99 [2] 91 b5 [2] bf 97 [2] ab 8c [2] a4 96 [2] ba 8b [2] b8 8a [2] a3 8c [2] bf 8b [2] a3 a4 }

  condition:
    any of them
}