rule TTP_XOR_QUAD_CurrentVersionRun_16cf {
  strings:
    $key_16cf = { 45 a0 [2] 61 ae [2] 4a 82 [2] 64 a0 [2] 70 bb [2] 7f a1 [2] 61 bc [2] 63 bd [2] 78 bb [2] 64 bc [2] 78 93 }

  condition:
    any of them
}