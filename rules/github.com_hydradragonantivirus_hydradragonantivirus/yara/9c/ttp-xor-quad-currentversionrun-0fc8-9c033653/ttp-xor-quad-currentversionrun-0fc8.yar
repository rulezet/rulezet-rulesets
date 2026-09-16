rule TTP_XOR_QUAD_CurrentVersionRun_0fc8 {
  strings:
    $key_0fc8 = { 5c a7 [2] 78 a9 [2] 53 85 [2] 7d a7 [2] 69 bc [2] 66 a6 [2] 78 bb [2] 7a ba [2] 61 bc [2] 7d bb [2] 61 94 }

  condition:
    any of them
}