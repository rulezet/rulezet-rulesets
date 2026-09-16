rule TTP_XOR_QUAD_CurrentVersionRun_0f96 {
  strings:
    $key_0f96 = { 5c f9 [2] 78 f7 [2] 53 db [2] 7d f9 [2] 69 e2 [2] 66 f8 [2] 78 e5 [2] 7a e4 [2] 61 e2 [2] 7d e5 [2] 61 ca }

  condition:
    any of them
}