rule TTP_XOR_QUAD_CurrentVersionRun_c5f3 {
  strings:
    $key_c5f3 = { 96 9c [2] b2 92 [2] 99 be [2] b7 9c [2] a3 87 [2] ac 9d [2] b2 80 [2] b0 81 [2] ab 87 [2] b7 80 [2] ab af }

  condition:
    any of them
}