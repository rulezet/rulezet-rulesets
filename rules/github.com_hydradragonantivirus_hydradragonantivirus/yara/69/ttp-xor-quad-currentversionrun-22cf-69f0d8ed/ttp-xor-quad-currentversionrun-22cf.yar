rule TTP_XOR_QUAD_CurrentVersionRun_22cf {
  strings:
    $key_22cf = { 71 a0 [2] 55 ae [2] 7e 82 [2] 50 a0 [2] 44 bb [2] 4b a1 [2] 55 bc [2] 57 bd [2] 4c bb [2] 50 bc [2] 4c 93 }

  condition:
    any of them
}