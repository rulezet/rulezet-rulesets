rule TTP_XOR_QUAD_CurrentVersionRun_27cf {
  strings:
    $key_27cf = { 74 a0 [2] 50 ae [2] 7b 82 [2] 55 a0 [2] 41 bb [2] 4e a1 [2] 50 bc [2] 52 bd [2] 49 bb [2] 55 bc [2] 49 93 }

  condition:
    any of them
}