rule TTP_XOR_QUAD_CurrentVersionRun_d760 {
  strings:
    $key_d760 = { 84 0f [2] a0 01 [2] 8b 2d [2] a5 0f [2] b1 14 [2] be 0e [2] a0 13 [2] a2 12 [2] b9 14 [2] a5 13 [2] b9 3c }

  condition:
    any of them
}