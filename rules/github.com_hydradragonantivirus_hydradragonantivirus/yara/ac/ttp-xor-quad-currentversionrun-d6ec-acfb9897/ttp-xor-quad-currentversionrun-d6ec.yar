rule TTP_XOR_QUAD_CurrentVersionRun_d6ec {
  strings:
    $key_d6ec = { 85 83 [2] a1 8d [2] 8a a1 [2] a4 83 [2] b0 98 [2] bf 82 [2] a1 9f [2] a3 9e [2] b8 98 [2] a4 9f [2] b8 b0 }

  condition:
    any of them
}