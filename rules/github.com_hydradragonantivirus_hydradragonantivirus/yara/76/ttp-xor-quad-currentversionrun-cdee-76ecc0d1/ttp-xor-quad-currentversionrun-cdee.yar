rule TTP_XOR_QUAD_CurrentVersionRun_cdee {
  strings:
    $key_cdee = { 9e 81 [2] ba 8f [2] 91 a3 [2] bf 81 [2] ab 9a [2] a4 80 [2] ba 9d [2] b8 9c [2] a3 9a [2] bf 9d [2] a3 b2 }

  condition:
    any of them
}