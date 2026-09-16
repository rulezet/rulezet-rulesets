rule TTP_XOR_QUAD_CurrentVersionRun_7ecf {
  strings:
    $key_7ecf = { 2d a0 [2] 09 ae [2] 22 82 [2] 0c a0 [2] 18 bb [2] 17 a1 [2] 09 bc [2] 0b bd [2] 10 bb [2] 0c bc [2] 10 93 }

  condition:
    any of them
}