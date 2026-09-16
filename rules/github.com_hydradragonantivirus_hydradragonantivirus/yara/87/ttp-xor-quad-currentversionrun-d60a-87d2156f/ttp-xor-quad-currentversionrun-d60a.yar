rule TTP_XOR_QUAD_CurrentVersionRun_d60a {
  strings:
    $key_d60a = { 85 65 [2] a1 6b [2] 8a 47 [2] a4 65 [2] b0 7e [2] bf 64 [2] a1 79 [2] a3 78 [2] b8 7e [2] a4 79 [2] b8 56 }

  condition:
    any of them
}