rule TTP_XOR_QUAD_CurrentVersionRun_ffcf {
  strings:
    $key_ffcf = { ac a0 [2] 88 ae [2] a3 82 [2] 8d a0 [2] 99 bb [2] 96 a1 [2] 88 bc [2] 8a bd [2] 91 bb [2] 8d bc [2] 91 93 }

  condition:
    any of them
}