rule TTP_XOR_QUAD_CurrentVersionRun_d1f0 {
  strings:
    $key_d1f0 = { 82 9f [2] a6 91 [2] 8d bd [2] a3 9f [2] b7 84 [2] b8 9e [2] a6 83 [2] a4 82 [2] bf 84 [2] a3 83 [2] bf ac }

  condition:
    any of them
}