rule TTP_XOR_QUAD_CurrentVersionRun_a05f {
  strings:
    $key_a05f = { f3 30 [2] d7 3e [2] fc 12 [2] d2 30 [2] c6 2b [2] c9 31 [2] d7 2c [2] d5 2d [2] ce 2b [2] d2 2c [2] ce 03 }

  condition:
    any of them
}