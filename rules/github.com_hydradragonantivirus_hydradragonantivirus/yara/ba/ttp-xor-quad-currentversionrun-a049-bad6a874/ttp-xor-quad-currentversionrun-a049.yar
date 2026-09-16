rule TTP_XOR_QUAD_CurrentVersionRun_a049 {
  strings:
    $key_a049 = { f3 26 [2] d7 28 [2] fc 04 [2] d2 26 [2] c6 3d [2] c9 27 [2] d7 3a [2] d5 3b [2] ce 3d [2] d2 3a [2] ce 15 }

  condition:
    any of them
}