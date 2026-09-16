rule TTP_XOR_QUAD_CurrentVersionRun_cd42 {
  strings:
    $key_cd42 = { 9e 2d [2] ba 23 [2] 91 0f [2] bf 2d [2] ab 36 [2] a4 2c [2] ba 31 [2] b8 30 [2] a3 36 [2] bf 31 [2] a3 1e }

  condition:
    any of them
}