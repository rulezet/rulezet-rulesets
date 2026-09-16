rule TTP_XOR_QUAD_CurrentVersionRun_a02c {
  strings:
    $key_a02c = { f3 43 [2] d7 4d [2] fc 61 [2] d2 43 [2] c6 58 [2] c9 42 [2] d7 5f [2] d5 5e [2] ce 58 [2] d2 5f [2] ce 70 }

  condition:
    any of them
}