rule TTP_XOR_QUAD_CurrentVersionRun_cd02 {
  strings:
    $key_cd02 = { 9e 6d [2] ba 63 [2] 91 4f [2] bf 6d [2] ab 76 [2] a4 6c [2] ba 71 [2] b8 70 [2] a3 76 [2] bf 71 [2] a3 5e }

  condition:
    any of them
}