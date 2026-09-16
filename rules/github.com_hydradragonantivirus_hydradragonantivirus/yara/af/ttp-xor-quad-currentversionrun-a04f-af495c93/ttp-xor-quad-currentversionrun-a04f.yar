rule TTP_XOR_QUAD_CurrentVersionRun_a04f {
  strings:
    $key_a04f = { f3 20 [2] d7 2e [2] fc 02 [2] d2 20 [2] c6 3b [2] c9 21 [2] d7 3c [2] d5 3d [2] ce 3b [2] d2 3c [2] ce 13 }

  condition:
    any of them
}