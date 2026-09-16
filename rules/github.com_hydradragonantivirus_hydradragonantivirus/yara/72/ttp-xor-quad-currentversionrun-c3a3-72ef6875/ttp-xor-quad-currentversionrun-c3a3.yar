rule TTP_XOR_QUAD_CurrentVersionRun_c3a3 {
  strings:
    $key_c3a3 = { 90 cc [2] b4 c2 [2] 9f ee [2] b1 cc [2] a5 d7 [2] aa cd [2] b4 d0 [2] b6 d1 [2] ad d7 [2] b1 d0 [2] ad ff }

  condition:
    any of them
}