rule TTP_XOR_QUAD_CurrentVersionRun_cd56 {
  strings:
    $key_cd56 = { 9e 39 [2] ba 37 [2] 91 1b [2] bf 39 [2] ab 22 [2] a4 38 [2] ba 25 [2] b8 24 [2] a3 22 [2] bf 25 [2] a3 0a }

  condition:
    any of them
}