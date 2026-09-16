rule TTP_XOR_QUAD_CurrentVersionRun_e3cf {
  strings:
    $key_e3cf = { b0 a0 [2] 94 ae [2] bf 82 [2] 91 a0 [2] 85 bb [2] 8a a1 [2] 94 bc [2] 96 bd [2] 8d bb [2] 91 bc [2] 8d 93 }

  condition:
    any of them
}