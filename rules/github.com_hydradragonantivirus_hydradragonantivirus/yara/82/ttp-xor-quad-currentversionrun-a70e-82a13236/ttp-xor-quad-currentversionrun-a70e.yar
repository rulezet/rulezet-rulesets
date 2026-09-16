rule TTP_XOR_QUAD_CurrentVersionRun_a70e {
  strings:
    $key_a70e = { f4 61 [2] d0 6f [2] fb 43 [2] d5 61 [2] c1 7a [2] ce 60 [2] d0 7d [2] d2 7c [2] c9 7a [2] d5 7d [2] c9 52 }

  condition:
    any of them
}