rule TTP_XOR_QUAD_CurrentVersionRun_a741 {
  strings:
    $key_a741 = { f4 2e [2] d0 20 [2] fb 0c [2] d5 2e [2] c1 35 [2] ce 2f [2] d0 32 [2] d2 33 [2] c9 35 [2] d5 32 [2] c9 1d }

  condition:
    any of them
}