rule TTP_XOR_QUAD_CurrentVersionRun_cdec {
  strings:
    $key_cdec = { 9e 83 [2] ba 8d [2] 91 a1 [2] bf 83 [2] ab 98 [2] a4 82 [2] ba 9f [2] b8 9e [2] a3 98 [2] bf 9f [2] a3 b0 }

  condition:
    any of them
}