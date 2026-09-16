rule TTP_XOR_QUAD_CurrentVersionRun_d1eb {
  strings:
    $key_d1eb = { 82 84 [2] a6 8a [2] 8d a6 [2] a3 84 [2] b7 9f [2] b8 85 [2] a6 98 [2] a4 99 [2] bf 9f [2] a3 98 [2] bf b7 }

  condition:
    any of them
}