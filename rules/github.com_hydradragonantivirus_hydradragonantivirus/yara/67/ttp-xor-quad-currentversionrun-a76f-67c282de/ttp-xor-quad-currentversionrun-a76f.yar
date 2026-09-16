rule TTP_XOR_QUAD_CurrentVersionRun_a76f {
  strings:
    $key_a76f = { f4 00 [2] d0 0e [2] fb 22 [2] d5 00 [2] c1 1b [2] ce 01 [2] d0 1c [2] d2 1d [2] c9 1b [2] d5 1c [2] c9 33 }

  condition:
    any of them
}