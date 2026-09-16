rule TTP_XOR_QUAD_CurrentVersionRun_d88d {
  strings:
    $key_d88d = { 8b e2 [2] af ec [2] 84 c0 [2] aa e2 [2] be f9 [2] b1 e3 [2] af fe [2] ad ff [2] b6 f9 [2] aa fe [2] b6 d1 }

  condition:
    any of them
}