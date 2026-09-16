rule TTP_XOR_QUAD_CurrentVersionRun_a06f {
  strings:
    $key_a06f = { f3 00 [2] d7 0e [2] fc 22 [2] d2 00 [2] c6 1b [2] c9 01 [2] d7 1c [2] d5 1d [2] ce 1b [2] d2 1c [2] ce 33 }

  condition:
    any of them
}