rule TTP_XOR_QUAD_CurrentVersionRun_a71d {
  strings:
    $key_a71d = { f4 72 [2] d0 7c [2] fb 50 [2] d5 72 [2] c1 69 [2] ce 73 [2] d0 6e [2] d2 6f [2] c9 69 [2] d5 6e [2] c9 41 }

  condition:
    any of them
}