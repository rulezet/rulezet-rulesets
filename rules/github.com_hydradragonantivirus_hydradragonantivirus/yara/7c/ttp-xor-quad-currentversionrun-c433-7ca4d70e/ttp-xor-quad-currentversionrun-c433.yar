rule TTP_XOR_QUAD_CurrentVersionRun_c433 {
  strings:
    $key_c433 = { 97 5c [2] b3 52 [2] 98 7e [2] b6 5c [2] a2 47 [2] ad 5d [2] b3 40 [2] b1 41 [2] aa 47 [2] b6 40 [2] aa 6f }

  condition:
    any of them
}