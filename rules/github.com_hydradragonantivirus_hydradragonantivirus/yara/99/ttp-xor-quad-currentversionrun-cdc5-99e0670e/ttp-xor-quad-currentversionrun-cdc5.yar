rule TTP_XOR_QUAD_CurrentVersionRun_cdc5 {
  strings:
    $key_cdc5 = { 9e aa [2] ba a4 [2] 91 88 [2] bf aa [2] ab b1 [2] a4 ab [2] ba b6 [2] b8 b7 [2] a3 b1 [2] bf b6 [2] a3 99 }

  condition:
    any of them
}