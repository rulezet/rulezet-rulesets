rule TTP_XOR_QUAD_CurrentVersionRun_3cc8 {
  strings:
    $key_3cc8 = { 6f a7 [2] 4b a9 [2] 60 85 [2] 4e a7 [2] 5a bc [2] 55 a6 [2] 4b bb [2] 49 ba [2] 52 bc [2] 4e bb [2] 52 94 }

  condition:
    any of them
}