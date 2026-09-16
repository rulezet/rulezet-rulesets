rule TTP_XOR_QUAD_CurrentVersionRun_41cf {
  strings:
    $key_41cf = { 12 a0 [2] 36 ae [2] 1d 82 [2] 33 a0 [2] 27 bb [2] 28 a1 [2] 36 bc [2] 34 bd [2] 2f bb [2] 33 bc [2] 2f 93 }

  condition:
    any of them
}