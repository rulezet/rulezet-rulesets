rule TTP_XOR_QUAD_CurrentVersionRun_edc9 {
  strings:
    $key_edc9 = { be a6 [2] 9a a8 [2] b1 84 [2] 9f a6 [2] 8b bd [2] 84 a7 [2] 9a ba [2] 98 bb [2] 83 bd [2] 9f ba [2] 83 95 }

  condition:
    any of them
}