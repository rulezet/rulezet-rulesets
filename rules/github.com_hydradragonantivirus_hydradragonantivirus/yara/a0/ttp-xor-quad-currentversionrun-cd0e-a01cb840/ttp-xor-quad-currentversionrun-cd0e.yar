rule TTP_XOR_QUAD_CurrentVersionRun_cd0e {
  strings:
    $key_cd0e = { 9e 61 [2] ba 6f [2] 91 43 [2] bf 61 [2] ab 7a [2] a4 60 [2] ba 7d [2] b8 7c [2] a3 7a [2] bf 7d [2] a3 52 }

  condition:
    any of them
}