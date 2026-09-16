rule TTP_XOR_QUAD_CurrentVersionRun_a05a {
  strings:
    $key_a05a = { f3 35 [2] d7 3b [2] fc 17 [2] d2 35 [2] c6 2e [2] c9 34 [2] d7 29 [2] d5 28 [2] ce 2e [2] d2 29 [2] ce 06 }

  condition:
    any of them
}