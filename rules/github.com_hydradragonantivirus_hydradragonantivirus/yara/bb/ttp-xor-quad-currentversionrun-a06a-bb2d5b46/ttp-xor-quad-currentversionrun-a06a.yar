rule TTP_XOR_QUAD_CurrentVersionRun_a06a {
  strings:
    $key_a06a = { f3 05 [2] d7 0b [2] fc 27 [2] d2 05 [2] c6 1e [2] c9 04 [2] d7 19 [2] d5 18 [2] ce 1e [2] d2 19 [2] ce 36 }

  condition:
    any of them
}