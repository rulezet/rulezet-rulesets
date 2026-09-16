rule TTP_XOR_QUAD_CurrentVersionRun_e4cf {
  strings:
    $key_e4cf = { b7 a0 [2] 93 ae [2] b8 82 [2] 96 a0 [2] 82 bb [2] 8d a1 [2] 93 bc [2] 91 bd [2] 8a bb [2] 96 bc [2] 8a 93 }

  condition:
    any of them
}