rule TTP_XOR_QUAD_CurrentVersionRun_a051 {
  strings:
    $key_a051 = { f3 3e [2] d7 30 [2] fc 1c [2] d2 3e [2] c6 25 [2] c9 3f [2] d7 22 [2] d5 23 [2] ce 25 [2] d2 22 [2] ce 0d }

  condition:
    any of them
}