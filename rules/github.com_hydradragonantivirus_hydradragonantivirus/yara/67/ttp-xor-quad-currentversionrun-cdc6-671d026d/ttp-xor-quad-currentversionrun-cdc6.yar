rule TTP_XOR_QUAD_CurrentVersionRun_cdc6 {
  strings:
    $key_cdc6 = { 9e a9 [2] ba a7 [2] 91 8b [2] bf a9 [2] ab b2 [2] a4 a8 [2] ba b5 [2] b8 b4 [2] a3 b2 [2] bf b5 [2] a3 9a }

  condition:
    any of them
}