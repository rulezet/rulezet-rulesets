rule TTP_XOR_QUAD_CurrentVersionRun_55cf {
  strings:
    $key_55cf = { 06 a0 [2] 22 ae [2] 09 82 [2] 27 a0 [2] 33 bb [2] 3c a1 [2] 22 bc [2] 20 bd [2] 3b bb [2] 27 bc [2] 3b 93 }

  condition:
    any of them
}