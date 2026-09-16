rule TTP_XOR_QUAD_CurrentVersionRun_cde7 {
  strings:
    $key_cde7 = { 9e 88 [2] ba 86 [2] 91 aa [2] bf 88 [2] ab 93 [2] a4 89 [2] ba 94 [2] b8 95 [2] a3 93 [2] bf 94 [2] a3 bb }

  condition:
    any of them
}