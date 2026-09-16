rule TTP_XOR_QUAD_CurrentVersionRun_24cf {
  strings:
    $key_24cf = { 77 a0 [2] 53 ae [2] 78 82 [2] 56 a0 [2] 42 bb [2] 4d a1 [2] 53 bc [2] 51 bd [2] 4a bb [2] 56 bc [2] 4a 93 }

  condition:
    any of them
}