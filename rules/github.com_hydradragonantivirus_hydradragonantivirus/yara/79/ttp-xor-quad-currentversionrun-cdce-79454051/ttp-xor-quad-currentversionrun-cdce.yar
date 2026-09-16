rule TTP_XOR_QUAD_CurrentVersionRun_cdce {
  strings:
    $key_cdce = { 9e a1 [2] ba af [2] 91 83 [2] bf a1 [2] ab ba [2] a4 a0 [2] ba bd [2] b8 bc [2] a3 ba [2] bf bd [2] a3 92 }

  condition:
    any of them
}