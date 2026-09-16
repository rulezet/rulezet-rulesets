rule TTP_XOR_QUAD_CurrentVersionRun_d6f0 {
  strings:
    $key_d6f0 = { 85 9f [2] a1 91 [2] 8a bd [2] a4 9f [2] b0 84 [2] bf 9e [2] a1 83 [2] a3 82 [2] b8 84 [2] a4 83 [2] b8 ac }

  condition:
    any of them
}