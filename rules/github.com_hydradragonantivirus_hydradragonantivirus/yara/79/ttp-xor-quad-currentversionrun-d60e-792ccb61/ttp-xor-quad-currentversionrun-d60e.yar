rule TTP_XOR_QUAD_CurrentVersionRun_d60e {
  strings:
    $key_d60e = { 85 61 [2] a1 6f [2] 8a 43 [2] a4 61 [2] b0 7a [2] bf 60 [2] a1 7d [2] a3 7c [2] b8 7a [2] a4 7d [2] b8 52 }

  condition:
    any of them
}