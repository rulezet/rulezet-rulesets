rule TTP_XOR_QUAD_CurrentVersionRun_1cc8 {
  strings:
    $key_1cc8 = { 4f a7 [2] 6b a9 [2] 40 85 [2] 6e a7 [2] 7a bc [2] 75 a6 [2] 6b bb [2] 69 ba [2] 72 bc [2] 6e bb [2] 72 94 }

  condition:
    any of them
}