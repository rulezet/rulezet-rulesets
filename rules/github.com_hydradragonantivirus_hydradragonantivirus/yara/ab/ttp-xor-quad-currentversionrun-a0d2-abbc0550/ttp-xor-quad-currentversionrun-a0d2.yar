rule TTP_XOR_QUAD_CurrentVersionRun_a0d2 {
  strings:
    $key_a0d2 = { f3 bd [2] d7 b3 [2] fc 9f [2] d2 bd [2] c6 a6 [2] c9 bc [2] d7 a1 [2] d5 a0 [2] ce a6 [2] d2 a1 [2] ce 8e }

  condition:
    any of them
}