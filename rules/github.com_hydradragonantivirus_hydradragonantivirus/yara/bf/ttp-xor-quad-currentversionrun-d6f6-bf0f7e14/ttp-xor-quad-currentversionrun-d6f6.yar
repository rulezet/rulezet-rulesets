rule TTP_XOR_QUAD_CurrentVersionRun_d6f6 {
  strings:
    $key_d6f6 = { 85 99 [2] a1 97 [2] 8a bb [2] a4 99 [2] b0 82 [2] bf 98 [2] a1 85 [2] a3 84 [2] b8 82 [2] a4 85 [2] b8 aa }

  condition:
    any of them
}