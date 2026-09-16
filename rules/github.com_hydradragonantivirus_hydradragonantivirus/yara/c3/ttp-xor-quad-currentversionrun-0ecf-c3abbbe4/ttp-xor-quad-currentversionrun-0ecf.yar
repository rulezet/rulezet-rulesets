rule TTP_XOR_QUAD_CurrentVersionRun_0ecf {
  strings:
    $key_0ecf = { 5d a0 [2] 79 ae [2] 52 82 [2] 7c a0 [2] 68 bb [2] 67 a1 [2] 79 bc [2] 7b bd [2] 60 bb [2] 7c bc [2] 60 93 }

  condition:
    any of them
}