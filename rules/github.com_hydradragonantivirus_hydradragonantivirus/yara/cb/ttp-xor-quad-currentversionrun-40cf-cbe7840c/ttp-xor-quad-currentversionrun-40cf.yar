rule TTP_XOR_QUAD_CurrentVersionRun_40cf {
  strings:
    $key_40cf = { 13 a0 [2] 37 ae [2] 1c 82 [2] 32 a0 [2] 26 bb [2] 29 a1 [2] 37 bc [2] 35 bd [2] 2e bb [2] 32 bc [2] 2e 93 }

  condition:
    any of them
}