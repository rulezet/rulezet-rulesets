rule TTP_XOR_QUAD_CurrentVersionRun_cd46 {
  strings:
    $key_cd46 = { 9e 29 [2] ba 27 [2] 91 0b [2] bf 29 [2] ab 32 [2] a4 28 [2] ba 35 [2] b8 34 [2] a3 32 [2] bf 35 [2] a3 1a }

  condition:
    any of them
}