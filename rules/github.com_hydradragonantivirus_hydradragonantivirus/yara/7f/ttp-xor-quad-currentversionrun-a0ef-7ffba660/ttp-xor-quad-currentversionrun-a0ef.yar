rule TTP_XOR_QUAD_CurrentVersionRun_a0ef {
  strings:
    $key_a0ef = { f3 80 [2] d7 8e [2] fc a2 [2] d2 80 [2] c6 9b [2] c9 81 [2] d7 9c [2] d5 9d [2] ce 9b [2] d2 9c [2] ce b3 }

  condition:
    any of them
}