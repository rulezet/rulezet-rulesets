rule TTP_XOR_QUAD_CurrentVersionRun_a740 {
  strings:
    $key_a740 = { f4 2f [2] d0 21 [2] fb 0d [2] d5 2f [2] c1 34 [2] ce 2e [2] d0 33 [2] d2 32 [2] c9 34 [2] d5 33 [2] c9 1c }

  condition:
    any of them
}