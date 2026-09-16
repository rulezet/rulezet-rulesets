rule TTP_XOR_QUAD_CurrentVersionRun_a77c {
  strings:
    $key_a77c = { f4 13 [2] d0 1d [2] fb 31 [2] d5 13 [2] c1 08 [2] ce 12 [2] d0 0f [2] d2 0e [2] c9 08 [2] d5 0f [2] c9 20 }

  condition:
    any of them
}