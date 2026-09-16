rule TTP_XOR_QUAD_CurrentVersionRun_efcf {
  strings:
    $key_efcf = { bc a0 [2] 98 ae [2] b3 82 [2] 9d a0 [2] 89 bb [2] 86 a1 [2] 98 bc [2] 9a bd [2] 81 bb [2] 9d bc [2] 81 93 }

  condition:
    any of them
}