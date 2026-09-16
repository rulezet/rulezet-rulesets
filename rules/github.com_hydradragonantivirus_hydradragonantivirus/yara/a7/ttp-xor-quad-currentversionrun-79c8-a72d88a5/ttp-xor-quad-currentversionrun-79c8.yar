rule TTP_XOR_QUAD_CurrentVersionRun_79c8 {
  strings:
    $key_79c8 = { 2a a7 [2] 0e a9 [2] 25 85 [2] 0b a7 [2] 1f bc [2] 10 a6 [2] 0e bb [2] 0c ba [2] 17 bc [2] 0b bb [2] 17 94 }

  condition:
    any of them
}