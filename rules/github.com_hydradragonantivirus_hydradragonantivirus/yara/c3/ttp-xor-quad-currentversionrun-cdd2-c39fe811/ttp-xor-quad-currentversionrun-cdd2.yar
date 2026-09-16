rule TTP_XOR_QUAD_CurrentVersionRun_cdd2 {
  strings:
    $key_cdd2 = { 9e bd [2] ba b3 [2] 91 9f [2] bf bd [2] ab a6 [2] a4 bc [2] ba a1 [2] b8 a0 [2] a3 a6 [2] bf a1 [2] a3 8e }

  condition:
    any of them
}