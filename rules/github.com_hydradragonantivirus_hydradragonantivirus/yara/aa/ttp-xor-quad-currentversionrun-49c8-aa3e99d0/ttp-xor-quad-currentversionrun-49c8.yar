rule TTP_XOR_QUAD_CurrentVersionRun_49c8 {
  strings:
    $key_49c8 = { 1a a7 [2] 3e a9 [2] 15 85 [2] 3b a7 [2] 2f bc [2] 20 a6 [2] 3e bb [2] 3c ba [2] 27 bc [2] 3b bb [2] 27 94 }

  condition:
    any of them
}