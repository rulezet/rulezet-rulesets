rule TTP_XOR_QUAD_CurrentVersionRun_c1ba {
  strings:
    $key_c1ba = { 92 d5 [2] b6 db [2] 9d f7 [2] b3 d5 [2] a7 ce [2] a8 d4 [2] b6 c9 [2] b4 c8 [2] af ce [2] b3 c9 [2] af e6 }

  condition:
    any of them
}