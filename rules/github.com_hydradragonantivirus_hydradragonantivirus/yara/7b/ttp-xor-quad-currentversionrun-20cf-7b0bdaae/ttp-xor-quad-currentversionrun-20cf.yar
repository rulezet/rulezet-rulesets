rule TTP_XOR_QUAD_CurrentVersionRun_20cf {
  strings:
    $key_20cf = { 73 a0 [2] 57 ae [2] 7c 82 [2] 52 a0 [2] 46 bb [2] 49 a1 [2] 57 bc [2] 55 bd [2] 4e bb [2] 52 bc [2] 4e 93 }

  condition:
    any of them
}