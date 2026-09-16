rule TTP_XOR_QUAD_CurrentVersionRun_72cf {
  strings:
    $key_72cf = { 21 a0 [2] 05 ae [2] 2e 82 [2] 00 a0 [2] 14 bb [2] 1b a1 [2] 05 bc [2] 07 bd [2] 1c bb [2] 00 bc [2] 1c 93 }

  condition:
    any of them
}