rule TTP_XOR_QUAD_CurrentVersionRun_cd2e {
  strings:
    $key_cd2e = { 9e 41 [2] ba 4f [2] 91 63 [2] bf 41 [2] ab 5a [2] a4 40 [2] ba 5d [2] b8 5c [2] a3 5a [2] bf 5d [2] a3 72 }

  condition:
    any of them
}