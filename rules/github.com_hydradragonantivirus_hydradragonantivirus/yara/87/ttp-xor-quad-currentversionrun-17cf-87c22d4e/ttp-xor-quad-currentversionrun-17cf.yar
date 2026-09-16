rule TTP_XOR_QUAD_CurrentVersionRun_17cf {
  strings:
    $key_17cf = { 44 a0 [2] 60 ae [2] 4b 82 [2] 65 a0 [2] 71 bb [2] 7e a1 [2] 60 bc [2] 62 bd [2] 79 bb [2] 65 bc [2] 79 93 }

  condition:
    any of them
}