rule TTP_XOR_QUAD_CurrentVersionRun_c381 {
  strings:
    $key_c381 = { 90 ee [2] b4 e0 [2] 9f cc [2] b1 ee [2] a5 f5 [2] aa ef [2] b4 f2 [2] b6 f3 [2] ad f5 [2] b1 f2 [2] ad dd }

  condition:
    any of them
}