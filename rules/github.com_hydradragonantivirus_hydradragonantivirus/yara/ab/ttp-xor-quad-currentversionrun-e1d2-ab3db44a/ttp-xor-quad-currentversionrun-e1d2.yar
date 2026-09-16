rule TTP_XOR_QUAD_CurrentVersionRun_e1d2 {
  strings:
    $key_e1d2 = { b2 bd [2] 96 b3 [2] bd 9f [2] 93 bd [2] 87 a6 [2] 88 bc [2] 96 a1 [2] 94 a0 [2] 8f a6 [2] 93 a1 [2] 8f 8e }

  condition:
    any of them
}