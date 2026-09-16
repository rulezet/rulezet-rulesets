rule TTP_XOR_QUAD_CurrentVersionRun_a04e {
  strings:
    $key_a04e = { f3 21 [2] d7 2f [2] fc 03 [2] d2 21 [2] c6 3a [2] c9 20 [2] d7 3d [2] d5 3c [2] ce 3a [2] d2 3d [2] ce 12 }

  condition:
    any of them
}