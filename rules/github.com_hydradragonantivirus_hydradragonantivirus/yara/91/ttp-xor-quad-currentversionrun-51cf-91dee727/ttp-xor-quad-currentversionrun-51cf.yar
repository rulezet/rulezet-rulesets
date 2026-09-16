rule TTP_XOR_QUAD_CurrentVersionRun_51cf {
  strings:
    $key_51cf = { 02 a0 [2] 26 ae [2] 0d 82 [2] 23 a0 [2] 37 bb [2] 38 a1 [2] 26 bc [2] 24 bd [2] 3f bb [2] 23 bc [2] 3f 93 }

  condition:
    any of them
}