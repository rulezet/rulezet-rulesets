rule TTP_XOR_QUAD_CurrentVersionRun_a04a {
  strings:
    $key_a04a = { f3 25 [2] d7 2b [2] fc 07 [2] d2 25 [2] c6 3e [2] c9 24 [2] d7 39 [2] d5 38 [2] ce 3e [2] d2 39 [2] ce 16 }

  condition:
    any of them
}