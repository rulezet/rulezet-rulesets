rule TTP_XOR_QUAD_CurrentVersionRun_cdea {
  strings:
    $key_cdea = { 9e 85 [2] ba 8b [2] 91 a7 [2] bf 85 [2] ab 9e [2] a4 84 [2] ba 99 [2] b8 98 [2] a3 9e [2] bf 99 [2] a3 b6 }

  condition:
    any of them
}