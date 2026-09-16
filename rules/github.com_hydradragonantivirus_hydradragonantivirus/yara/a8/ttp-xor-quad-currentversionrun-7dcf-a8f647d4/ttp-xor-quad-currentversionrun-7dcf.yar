rule TTP_XOR_QUAD_CurrentVersionRun_7dcf {
  strings:
    $key_7dcf = { 2e a0 [2] 0a ae [2] 21 82 [2] 0f a0 [2] 1b bb [2] 14 a1 [2] 0a bc [2] 08 bd [2] 13 bb [2] 0f bc [2] 13 93 }

  condition:
    any of them
}