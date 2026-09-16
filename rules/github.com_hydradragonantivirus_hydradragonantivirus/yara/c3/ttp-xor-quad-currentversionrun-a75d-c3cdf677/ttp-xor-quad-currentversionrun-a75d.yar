rule TTP_XOR_QUAD_CurrentVersionRun_a75d {
  strings:
    $key_a75d = { f4 32 [2] d0 3c [2] fb 10 [2] d5 32 [2] c1 29 [2] ce 33 [2] d0 2e [2] d2 2f [2] c9 29 [2] d5 2e [2] c9 01 }

  condition:
    any of them
}