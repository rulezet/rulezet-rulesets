rule TTP_XOR_QUAD_CurrentVersionRun_1ecf {
  strings:
    $key_1ecf = { 4d a0 [2] 69 ae [2] 42 82 [2] 6c a0 [2] 78 bb [2] 77 a1 [2] 69 bc [2] 6b bd [2] 70 bb [2] 6c bc [2] 70 93 }

  condition:
    any of them
}