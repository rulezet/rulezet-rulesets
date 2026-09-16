rule TTP_XOR_QUAD_CurrentVersionRun_c2c9 {
  strings:
    $key_c2c9 = { 91 a6 [2] b5 a8 [2] 9e 84 [2] b0 a6 [2] a4 bd [2] ab a7 [2] b5 ba [2] b7 bb [2] ac bd [2] b0 ba [2] ac 95 }

  condition:
    any of them
}