rule TTP_XOR_QUAD_CurrentVersionRun_cdd1 {
  strings:
    $key_cdd1 = { 9e be [2] ba b0 [2] 91 9c [2] bf be [2] ab a5 [2] a4 bf [2] ba a2 [2] b8 a3 [2] a3 a5 [2] bf a2 [2] a3 8d }

  condition:
    any of them
}