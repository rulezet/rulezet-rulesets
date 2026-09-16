rule TTP_XOR_QUAD_CurrentVersionRun_ddbf {
  strings:
    $key_ddbf = { 8e d0 [2] aa de [2] 81 f2 [2] af d0 [2] bb cb [2] b4 d1 [2] aa cc [2] a8 cd [2] b3 cb [2] af cc [2] b3 e3 }

  condition:
    any of them
}