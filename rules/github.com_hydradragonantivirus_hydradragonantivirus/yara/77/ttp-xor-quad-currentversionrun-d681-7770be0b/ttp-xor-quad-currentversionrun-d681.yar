rule TTP_XOR_QUAD_CurrentVersionRun_d681 {
  strings:
    $key_d681 = { 85 ee [2] a1 e0 [2] 8a cc [2] a4 ee [2] b0 f5 [2] bf ef [2] a1 f2 [2] a3 f3 [2] b8 f5 [2] a4 f2 [2] b8 dd }

  condition:
    any of them
}