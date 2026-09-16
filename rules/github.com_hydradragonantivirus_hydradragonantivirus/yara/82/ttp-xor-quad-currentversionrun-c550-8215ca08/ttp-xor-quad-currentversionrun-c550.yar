rule TTP_XOR_QUAD_CurrentVersionRun_c550 {
  strings:
    $key_c550 = { 96 3f [2] b2 31 [2] 99 1d [2] b7 3f [2] a3 24 [2] ac 3e [2] b2 23 [2] b0 22 [2] ab 24 [2] b7 23 [2] ab 0c }

  condition:
    any of them
}