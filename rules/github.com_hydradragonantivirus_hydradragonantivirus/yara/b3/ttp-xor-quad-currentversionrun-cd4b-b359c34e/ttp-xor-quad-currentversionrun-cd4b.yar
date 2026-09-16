rule TTP_XOR_QUAD_CurrentVersionRun_cd4b {
  strings:
    $key_cd4b = { 9e 24 [2] ba 2a [2] 91 06 [2] bf 24 [2] ab 3f [2] a4 25 [2] ba 38 [2] b8 39 [2] a3 3f [2] bf 38 [2] a3 17 }

  condition:
    any of them
}