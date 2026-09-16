rule TTP_XOR_QUAD_CurrentVersionRun_a02b {
  strings:
    $key_a02b = { f3 44 [2] d7 4a [2] fc 66 [2] d2 44 [2] c6 5f [2] c9 45 [2] d7 58 [2] d5 59 [2] ce 5f [2] d2 58 [2] ce 77 }

  condition:
    any of them
}