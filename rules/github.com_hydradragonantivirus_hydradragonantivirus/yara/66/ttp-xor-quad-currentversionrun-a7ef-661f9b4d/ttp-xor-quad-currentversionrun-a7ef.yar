rule TTP_XOR_QUAD_CurrentVersionRun_a7ef {
  strings:
    $key_a7ef = { f4 80 [2] d0 8e [2] fb a2 [2] d5 80 [2] c1 9b [2] ce 81 [2] d0 9c [2] d2 9d [2] c9 9b [2] d5 9c [2] c9 b3 }

  condition:
    any of them
}