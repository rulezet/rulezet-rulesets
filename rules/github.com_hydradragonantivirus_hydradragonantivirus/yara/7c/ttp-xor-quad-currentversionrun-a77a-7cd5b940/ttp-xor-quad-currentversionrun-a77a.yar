rule TTP_XOR_QUAD_CurrentVersionRun_a77a {
  strings:
    $key_a77a = { f4 15 [2] d0 1b [2] fb 37 [2] d5 15 [2] c1 0e [2] ce 14 [2] d0 09 [2] d2 08 [2] c9 0e [2] d5 09 [2] c9 26 }

  condition:
    any of them
}