rule TTP_XOR_QUAD_CurrentVersionRun_d64a {
  strings:
    $key_d64a = { 85 25 [2] a1 2b [2] 8a 07 [2] a4 25 [2] b0 3e [2] bf 24 [2] a1 39 [2] a3 38 [2] b8 3e [2] a4 39 [2] b8 16 }

  condition:
    any of them
}