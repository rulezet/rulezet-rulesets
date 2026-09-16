rule TTP_XOR_QUAD_CurrentVersionRun_c537 {
  strings:
    $key_c537 = { 96 58 [2] b2 56 [2] 99 7a [2] b7 58 [2] a3 43 [2] ac 59 [2] b2 44 [2] b0 45 [2] ab 43 [2] b7 44 [2] ab 6b }

  condition:
    any of them
}