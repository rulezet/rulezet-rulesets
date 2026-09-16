rule TTP_XOR_QUAD_CurrentVersionRun_d700 {
  strings:
    $key_d700 = { 84 6f [2] a0 61 [2] 8b 4d [2] a5 6f [2] b1 74 [2] be 6e [2] a0 73 [2] a2 72 [2] b9 74 [2] a5 73 [2] b9 5c }

  condition:
    any of them
}