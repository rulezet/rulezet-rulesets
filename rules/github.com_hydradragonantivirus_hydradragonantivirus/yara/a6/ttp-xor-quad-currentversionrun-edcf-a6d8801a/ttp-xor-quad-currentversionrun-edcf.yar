rule TTP_XOR_QUAD_CurrentVersionRun_edcf {
  strings:
    $key_edcf = { be a0 [2] 9a ae [2] b1 82 [2] 9f a0 [2] 8b bb [2] 84 a1 [2] 9a bc [2] 98 bd [2] 83 bb [2] 9f bc [2] 83 93 }

  condition:
    any of them
}