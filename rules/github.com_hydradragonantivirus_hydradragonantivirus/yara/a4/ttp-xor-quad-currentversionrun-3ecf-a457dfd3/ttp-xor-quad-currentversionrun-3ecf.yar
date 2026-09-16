rule TTP_XOR_QUAD_CurrentVersionRun_3ecf {
  strings:
    $key_3ecf = { 6d a0 [2] 49 ae [2] 62 82 [2] 4c a0 [2] 58 bb [2] 57 a1 [2] 49 bc [2] 4b bd [2] 50 bb [2] 4c bc [2] 50 93 }

  condition:
    any of them
}