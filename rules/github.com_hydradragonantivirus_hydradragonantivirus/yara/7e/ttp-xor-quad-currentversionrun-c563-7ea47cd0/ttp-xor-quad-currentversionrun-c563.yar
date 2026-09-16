rule TTP_XOR_QUAD_CurrentVersionRun_c563 {
  strings:
    $key_c563 = { 96 0c [2] b2 02 [2] 99 2e [2] b7 0c [2] a3 17 [2] ac 0d [2] b2 10 [2] b0 11 [2] ab 17 [2] b7 10 [2] ab 3f }

  condition:
    any of them
}