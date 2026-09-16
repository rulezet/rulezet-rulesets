rule TTP_XOR_QUAD_CurrentVersionRun_cdd4 {
  strings:
    $key_cdd4 = { 9e bb [2] ba b5 [2] 91 99 [2] bf bb [2] ab a0 [2] a4 ba [2] ba a7 [2] b8 a6 [2] a3 a0 [2] bf a7 [2] a3 88 }

  condition:
    any of them
}