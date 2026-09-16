rule TTP_XOR_QUAD_CurrentVersionRun_cdf9 {
  strings:
    $key_cdf9 = { 9e 96 [2] ba 98 [2] 91 b4 [2] bf 96 [2] ab 8d [2] a4 97 [2] ba 8a [2] b8 8b [2] a3 8d [2] bf 8a [2] a3 a5 }

  condition:
    any of them
}