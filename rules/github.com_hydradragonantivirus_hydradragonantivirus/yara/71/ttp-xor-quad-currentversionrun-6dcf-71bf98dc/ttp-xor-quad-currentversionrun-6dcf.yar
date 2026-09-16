rule TTP_XOR_QUAD_CurrentVersionRun_6dcf {
  strings:
    $key_6dcf = { 3e a0 [2] 1a ae [2] 31 82 [2] 1f a0 [2] 0b bb [2] 04 a1 [2] 1a bc [2] 18 bd [2] 03 bb [2] 1f bc [2] 03 93 }

  condition:
    any of them
}