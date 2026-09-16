rule TTP_XOR_QUAD_CurrentVersionRun_c333 {
  strings:
    $key_c333 = { 90 5c [2] b4 52 [2] 9f 7e [2] b1 5c [2] a5 47 [2] aa 5d [2] b4 40 [2] b6 41 [2] ad 47 [2] b1 40 [2] ad 6f }

  condition:
    any of them
}