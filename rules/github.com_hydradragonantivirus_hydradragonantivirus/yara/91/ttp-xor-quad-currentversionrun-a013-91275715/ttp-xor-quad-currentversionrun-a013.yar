rule TTP_XOR_QUAD_CurrentVersionRun_a013 {
  strings:
    $key_a013 = { f3 7c [2] d7 72 [2] fc 5e [2] d2 7c [2] c6 67 [2] c9 7d [2] d7 60 [2] d5 61 [2] ce 67 [2] d2 60 [2] ce 4f }

  condition:
    any of them
}