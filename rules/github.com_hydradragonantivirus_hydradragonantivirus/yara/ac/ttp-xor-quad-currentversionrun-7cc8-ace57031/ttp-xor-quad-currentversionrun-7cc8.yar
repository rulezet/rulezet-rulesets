rule TTP_XOR_QUAD_CurrentVersionRun_7cc8 {
  strings:
    $key_7cc8 = { 2f a7 [2] 0b a9 [2] 20 85 [2] 0e a7 [2] 1a bc [2] 15 a6 [2] 0b bb [2] 09 ba [2] 12 bc [2] 0e bb [2] 12 94 }

  condition:
    any of them
}