rule TTP_XOR_QUAD_CurrentVersionRun_b075 {
  strings:
    $key_b075 = { e3 1a [2] c7 14 [2] ec 38 [2] c2 1a [2] d6 01 [2] d9 1b [2] c7 06 [2] c5 07 [2] de 01 [2] c2 06 [2] de 29 }

  condition:
    any of them
}