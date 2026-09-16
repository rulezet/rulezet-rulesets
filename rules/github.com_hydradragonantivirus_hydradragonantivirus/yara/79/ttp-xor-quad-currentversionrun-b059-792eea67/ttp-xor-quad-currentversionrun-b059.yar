rule TTP_XOR_QUAD_CurrentVersionRun_b059 {
  strings:
    $key_b059 = { e3 36 [2] c7 38 [2] ec 14 [2] c2 36 [2] d6 2d [2] d9 37 [2] c7 2a [2] c5 2b [2] de 2d [2] c2 2a [2] de 05 }

  condition:
    any of them
}