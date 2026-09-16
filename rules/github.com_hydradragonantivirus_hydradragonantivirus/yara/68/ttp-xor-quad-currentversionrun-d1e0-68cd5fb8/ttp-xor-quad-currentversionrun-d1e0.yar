rule TTP_XOR_QUAD_CurrentVersionRun_d1e0 {
  strings:
    $key_d1e0 = { 82 8f [2] a6 81 [2] 8d ad [2] a3 8f [2] b7 94 [2] b8 8e [2] a6 93 [2] a4 92 [2] bf 94 [2] a3 93 [2] bf bc }

  condition:
    any of them
}