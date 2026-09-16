rule TTP_XOR_QUAD_CurrentVersionRun_a06b {
  strings:
    $key_a06b = { f3 04 [2] d7 0a [2] fc 26 [2] d2 04 [2] c6 1f [2] c9 05 [2] d7 18 [2] d5 19 [2] ce 1f [2] d2 18 [2] ce 37 }

  condition:
    any of them
}