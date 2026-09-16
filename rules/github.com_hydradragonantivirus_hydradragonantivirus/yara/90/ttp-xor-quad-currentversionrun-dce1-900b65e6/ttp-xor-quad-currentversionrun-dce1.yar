rule TTP_XOR_QUAD_CurrentVersionRun_dce1 {
  strings:
    $key_dce1 = { 8f 8e [2] ab 80 [2] 80 ac [2] ae 8e [2] ba 95 [2] b5 8f [2] ab 92 [2] a9 93 [2] b2 95 [2] ae 92 [2] b2 bd }

  condition:
    any of them
}