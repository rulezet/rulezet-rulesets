rule TTP_XOR_QUAD_CurrentVersionRun_a033 {
  strings:
    $key_a033 = { f3 5c [2] d7 52 [2] fc 7e [2] d2 5c [2] c6 47 [2] c9 5d [2] d7 40 [2] d5 41 [2] ce 47 [2] d2 40 [2] ce 6f }

  condition:
    any of them
}