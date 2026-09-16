rule TTP_XOR_QUAD_CurrentVersionRun_cde4 {
  strings:
    $key_cde4 = { 9e 8b [2] ba 85 [2] 91 a9 [2] bf 8b [2] ab 90 [2] a4 8a [2] ba 97 [2] b8 96 [2] a3 90 [2] bf 97 [2] a3 b8 }

  condition:
    any of them
}