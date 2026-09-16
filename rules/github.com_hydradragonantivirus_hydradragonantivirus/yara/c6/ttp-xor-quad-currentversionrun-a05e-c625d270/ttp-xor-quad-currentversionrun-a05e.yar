rule TTP_XOR_QUAD_CurrentVersionRun_a05e {
  strings:
    $key_a05e = { f3 31 [2] d7 3f [2] fc 13 [2] d2 31 [2] c6 2a [2] c9 30 [2] d7 2d [2] d5 2c [2] ce 2a [2] d2 2d [2] ce 02 }

  condition:
    any of them
}