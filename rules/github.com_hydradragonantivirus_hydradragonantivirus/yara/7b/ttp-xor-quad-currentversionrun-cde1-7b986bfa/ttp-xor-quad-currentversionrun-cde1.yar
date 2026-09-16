rule TTP_XOR_QUAD_CurrentVersionRun_cde1 {
  strings:
    $key_cde1 = { 9e 8e [2] ba 80 [2] 91 ac [2] bf 8e [2] ab 95 [2] a4 8f [2] ba 92 [2] b8 93 [2] a3 95 [2] bf 92 [2] a3 bd }

  condition:
    any of them
}