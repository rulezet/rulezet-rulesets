rule TTP_XOR_QUAD_CurrentVersionRun_cdb2 {
  strings:
    $key_cdb2 = { 9e dd [2] ba d3 [2] 91 ff [2] bf dd [2] ab c6 [2] a4 dc [2] ba c1 [2] b8 c0 [2] a3 c6 [2] bf c1 [2] a3 ee }

  condition:
    any of them
}