rule TTP_XOR_QUAD_CurrentVersionRun_cdfe {
  strings:
    $key_cdfe = { 9e 91 [2] ba 9f [2] 91 b3 [2] bf 91 [2] ab 8a [2] a4 90 [2] ba 8d [2] b8 8c [2] a3 8a [2] bf 8d [2] a3 a2 }

  condition:
    any of them
}