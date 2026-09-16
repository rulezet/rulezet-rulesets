rule TTP_XOR_QUAD_CurrentVersionRun_cd41 {
  strings:
    $key_cd41 = { 9e 2e [2] ba 20 [2] 91 0c [2] bf 2e [2] ab 35 [2] a4 2f [2] ba 32 [2] b8 33 [2] a3 35 [2] bf 32 [2] a3 1d }

  condition:
    any of them
}