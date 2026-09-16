rule TTP_XOR_QUAD_CurrentVersionRun_a713 {
  strings:
    $key_a713 = { f4 7c [2] d0 72 [2] fb 5e [2] d5 7c [2] c1 67 [2] ce 7d [2] d0 60 [2] d2 61 [2] c9 67 [2] d5 60 [2] c9 4f }

  condition:
    any of them
}