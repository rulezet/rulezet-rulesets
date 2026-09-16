rule TTP_XOR_QUAD_CurrentVersionRun_32cf {
  strings:
    $key_32cf = { 61 a0 [2] 45 ae [2] 6e 82 [2] 40 a0 [2] 54 bb [2] 5b a1 [2] 45 bc [2] 47 bd [2] 5c bb [2] 40 bc [2] 5c 93 }

  condition:
    any of them
}