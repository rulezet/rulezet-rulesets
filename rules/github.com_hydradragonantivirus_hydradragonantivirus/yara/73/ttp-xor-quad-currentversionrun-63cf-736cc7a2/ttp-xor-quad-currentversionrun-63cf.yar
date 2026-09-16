rule TTP_XOR_QUAD_CurrentVersionRun_63cf {
  strings:
    $key_63cf = { 30 a0 [2] 14 ae [2] 3f 82 [2] 11 a0 [2] 05 bb [2] 0a a1 [2] 14 bc [2] 16 bd [2] 0d bb [2] 11 bc [2] 0d 93 }

  condition:
    any of them
}