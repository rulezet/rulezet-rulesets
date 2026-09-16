rule TTP_XOR_QUAD_CurrentVersionRun_cdff {
  strings:
    $key_cdff = { 9e 90 [2] ba 9e [2] 91 b2 [2] bf 90 [2] ab 8b [2] a4 91 [2] ba 8c [2] b8 8d [2] a3 8b [2] bf 8c [2] a3 a3 }

  condition:
    any of them
}