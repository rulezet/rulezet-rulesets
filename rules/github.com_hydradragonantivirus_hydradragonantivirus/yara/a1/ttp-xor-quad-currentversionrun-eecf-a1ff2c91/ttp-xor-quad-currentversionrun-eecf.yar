rule TTP_XOR_QUAD_CurrentVersionRun_eecf {
  strings:
    $key_eecf = { bd a0 [2] 99 ae [2] b2 82 [2] 9c a0 [2] 88 bb [2] 87 a1 [2] 99 bc [2] 9b bd [2] 80 bb [2] 9c bc [2] 80 93 }

  condition:
    any of them
}