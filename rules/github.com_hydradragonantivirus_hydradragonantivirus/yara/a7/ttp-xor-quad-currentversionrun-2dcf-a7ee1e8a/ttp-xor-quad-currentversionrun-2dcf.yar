rule TTP_XOR_QUAD_CurrentVersionRun_2dcf {
  strings:
    $key_2dcf = { 7e a0 [2] 5a ae [2] 71 82 [2] 5f a0 [2] 4b bb [2] 44 a1 [2] 5a bc [2] 58 bd [2] 43 bb [2] 5f bc [2] 43 93 }

  condition:
    any of them
}