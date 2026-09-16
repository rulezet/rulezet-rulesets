rule TTP_XOR_QUAD_CurrentVersionRun_69c8 {
  strings:
    $key_69c8 = { 3a a7 [2] 1e a9 [2] 35 85 [2] 1b a7 [2] 0f bc [2] 00 a6 [2] 1e bb [2] 1c ba [2] 07 bc [2] 1b bb [2] 07 94 }

  condition:
    any of them
}