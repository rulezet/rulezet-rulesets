rule TTP_XOR_QUAD_CurrentVersionRun_cdf6 {
  strings:
    $key_cdf6 = { 9e 99 [2] ba 97 [2] 91 bb [2] bf 99 [2] ab 82 [2] a4 98 [2] ba 85 [2] b8 84 [2] a3 82 [2] bf 85 [2] a3 aa }

  condition:
    any of them
}