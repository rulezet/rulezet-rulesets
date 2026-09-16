rule TTP_XOR_QUAD_CurrentVersionRun_52cf {
  strings:
    $key_52cf = { 01 a0 [2] 25 ae [2] 0e 82 [2] 20 a0 [2] 34 bb [2] 3b a1 [2] 25 bc [2] 27 bd [2] 3c bb [2] 20 bc [2] 3c 93 }

  condition:
    any of them
}