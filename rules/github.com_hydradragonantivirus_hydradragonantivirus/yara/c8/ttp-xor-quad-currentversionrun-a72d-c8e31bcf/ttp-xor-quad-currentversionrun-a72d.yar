rule TTP_XOR_QUAD_CurrentVersionRun_a72d {
  strings:
    $key_a72d = { f4 42 [2] d0 4c [2] fb 60 [2] d5 42 [2] c1 59 [2] ce 43 [2] d0 5e [2] d2 5f [2] c9 59 [2] d5 5e [2] c9 71 }

  condition:
    any of them
}