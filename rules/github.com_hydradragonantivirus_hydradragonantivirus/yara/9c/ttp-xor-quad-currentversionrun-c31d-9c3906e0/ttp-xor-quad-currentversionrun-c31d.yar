rule TTP_XOR_QUAD_CurrentVersionRun_c31d {
  strings:
    $key_c31d = { 90 72 [2] b4 7c [2] 9f 50 [2] b1 72 [2] a5 69 [2] aa 73 [2] b4 6e [2] b6 6f [2] ad 69 [2] b1 6e [2] ad 41 }

  condition:
    any of them
}