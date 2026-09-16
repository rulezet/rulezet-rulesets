rule TTP_XOR_QUAD_CurrentVersionRun_a70f {
  strings:
    $key_a70f = { f4 60 [2] d0 6e [2] fb 42 [2] d5 60 [2] c1 7b [2] ce 61 [2] d0 7c [2] d2 7d [2] c9 7b [2] d5 7c [2] c9 53 }

  condition:
    any of them
}