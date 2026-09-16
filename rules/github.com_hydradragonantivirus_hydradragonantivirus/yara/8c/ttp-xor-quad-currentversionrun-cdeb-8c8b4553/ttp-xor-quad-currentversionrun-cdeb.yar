rule TTP_XOR_QUAD_CurrentVersionRun_cdeb {
  strings:
    $key_cdeb = { 9e 84 [2] ba 8a [2] 91 a6 [2] bf 84 [2] ab 9f [2] a4 85 [2] ba 98 [2] b8 99 [2] a3 9f [2] bf 98 [2] a3 b7 }

  condition:
    any of them
}