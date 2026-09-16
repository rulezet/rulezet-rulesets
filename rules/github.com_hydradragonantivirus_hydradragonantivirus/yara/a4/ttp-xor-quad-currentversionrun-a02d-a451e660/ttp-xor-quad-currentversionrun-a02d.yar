rule TTP_XOR_QUAD_CurrentVersionRun_a02d {
  strings:
    $key_a02d = { f3 42 [2] d7 4c [2] fc 60 [2] d2 42 [2] c6 59 [2] c9 43 [2] d7 5e [2] d5 5f [2] ce 59 [2] d2 5e [2] ce 71 }

  condition:
    any of them
}