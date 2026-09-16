rule TTP_XOR_QUAD_CurrentVersionRun_a026 {
  strings:
    $key_a026 = { f3 49 [2] d7 47 [2] fc 6b [2] d2 49 [2] c6 52 [2] c9 48 [2] d7 55 [2] d5 54 [2] ce 52 [2] d2 55 [2] ce 7a }

  condition:
    any of them
}