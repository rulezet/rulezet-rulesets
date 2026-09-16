rule TTP_XOR_QUAD_CurrentVersionRun_4cc8 {
  strings:
    $key_4cc8 = { 1f a7 [2] 3b a9 [2] 10 85 [2] 3e a7 [2] 2a bc [2] 25 a6 [2] 3b bb [2] 39 ba [2] 22 bc [2] 3e bb [2] 22 94 }

  condition:
    any of them
}