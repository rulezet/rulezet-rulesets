rule TTP_XOR_QUAD_CurrentVersionRun_cde2 {
  strings:
    $key_cde2 = { 9e 8d [2] ba 83 [2] 91 af [2] bf 8d [2] ab 96 [2] a4 8c [2] ba 91 [2] b8 90 [2] a3 96 [2] bf 91 [2] a3 be }

  condition:
    any of them
}