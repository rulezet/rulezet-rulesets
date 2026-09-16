rule TTP_XOR_QUAD_CurrentVersionRun_c560 {
  strings:
    $key_c560 = { 96 0f [2] b2 01 [2] 99 2d [2] b7 0f [2] a3 14 [2] ac 0e [2] b2 13 [2] b0 12 [2] ab 14 [2] b7 13 [2] ab 3c }

  condition:
    any of them
}