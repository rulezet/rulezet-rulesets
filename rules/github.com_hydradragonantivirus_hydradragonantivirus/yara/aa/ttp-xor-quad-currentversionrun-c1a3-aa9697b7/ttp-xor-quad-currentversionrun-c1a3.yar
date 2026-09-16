rule TTP_XOR_QUAD_CurrentVersionRun_c1a3 {
  strings:
    $key_c1a3 = { 92 cc [2] b6 c2 [2] 9d ee [2] b3 cc [2] a7 d7 [2] a8 cd [2] b6 d0 [2] b4 d1 [2] af d7 [2] b3 d0 [2] af ff }

  condition:
    any of them
}