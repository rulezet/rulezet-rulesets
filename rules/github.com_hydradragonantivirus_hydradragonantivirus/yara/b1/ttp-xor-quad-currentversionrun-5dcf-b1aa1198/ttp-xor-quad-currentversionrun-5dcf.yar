rule TTP_XOR_QUAD_CurrentVersionRun_5dcf {
  strings:
    $key_5dcf = { 0e a0 [2] 2a ae [2] 01 82 [2] 2f a0 [2] 3b bb [2] 34 a1 [2] 2a bc [2] 28 bd [2] 33 bb [2] 2f bc [2] 33 93 }

  condition:
    any of them
}