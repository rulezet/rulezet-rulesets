rule TTP_XOR_QUAD_CurrentVersionRun_a009 {
  strings:
    $key_a009 = { f3 66 [2] d7 68 [2] fc 44 [2] d2 66 [2] c6 7d [2] c9 67 [2] d7 7a [2] d5 7b [2] ce 7d [2] d2 7a [2] ce 55 }

  condition:
    any of them
}