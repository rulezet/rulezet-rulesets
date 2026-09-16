rule TTP_XOR_QUAD_CurrentVersionRun_a70a {
  strings:
    $key_a70a = { f4 65 [2] d0 6b [2] fb 47 [2] d5 65 [2] c1 7e [2] ce 64 [2] d0 79 [2] d2 78 [2] c9 7e [2] d5 79 [2] c9 56 }

  condition:
    any of them
}