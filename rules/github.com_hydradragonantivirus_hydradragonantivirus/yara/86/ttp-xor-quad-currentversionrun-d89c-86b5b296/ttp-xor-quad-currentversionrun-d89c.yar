rule TTP_XOR_QUAD_CurrentVersionRun_d89c {
  strings:
    $key_d89c = { 8b f3 [2] af fd [2] 84 d1 [2] aa f3 [2] be e8 [2] b1 f2 [2] af ef [2] ad ee [2] b6 e8 [2] aa ef [2] b6 c0 }

  condition:
    any of them
}