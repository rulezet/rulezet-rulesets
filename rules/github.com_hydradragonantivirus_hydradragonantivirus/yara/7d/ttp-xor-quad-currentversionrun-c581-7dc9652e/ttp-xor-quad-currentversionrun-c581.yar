rule TTP_XOR_QUAD_CurrentVersionRun_c581 {
  strings:
    $key_c581 = { 96 ee [2] b2 e0 [2] 99 cc [2] b7 ee [2] a3 f5 [2] ac ef [2] b2 f2 [2] b0 f3 [2] ab f5 [2] b7 f2 [2] ab dd }

  condition:
    any of them
}