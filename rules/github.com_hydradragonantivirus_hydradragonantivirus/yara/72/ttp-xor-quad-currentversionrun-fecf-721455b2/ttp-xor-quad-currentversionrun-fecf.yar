rule TTP_XOR_QUAD_CurrentVersionRun_fecf {
  strings:
    $key_fecf = { ad a0 [2] 89 ae [2] a2 82 [2] 8c a0 [2] 98 bb [2] 97 a1 [2] 89 bc [2] 8b bd [2] 90 bb [2] 8c bc [2] 90 93 }

  condition:
    any of them
}