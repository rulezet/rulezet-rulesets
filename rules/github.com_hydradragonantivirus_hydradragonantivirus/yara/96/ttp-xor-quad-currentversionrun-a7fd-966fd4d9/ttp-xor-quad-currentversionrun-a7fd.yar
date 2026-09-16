rule TTP_XOR_QUAD_CurrentVersionRun_a7fd {
  strings:
    $key_a7fd = { f4 92 [2] d0 9c [2] fb b0 [2] d5 92 [2] c1 89 [2] ce 93 [2] d0 8e [2] d2 8f [2] c9 89 [2] d5 8e [2] c9 a1 }

  condition:
    any of them
}