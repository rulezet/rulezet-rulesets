rule TTP_XOR_QUAD_CurrentVersionRun_cd53 {
  strings:
    $key_cd53 = { 9e 3c [2] ba 32 [2] 91 1e [2] bf 3c [2] ab 27 [2] a4 3d [2] ba 20 [2] b8 21 [2] a3 27 [2] bf 20 [2] a3 0f }

  condition:
    any of them
}