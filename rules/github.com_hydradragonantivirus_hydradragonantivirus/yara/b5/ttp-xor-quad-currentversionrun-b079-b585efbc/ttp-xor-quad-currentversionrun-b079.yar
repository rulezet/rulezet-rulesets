rule TTP_XOR_QUAD_CurrentVersionRun_b079 {
  strings:
    $key_b079 = { e3 16 [2] c7 18 [2] ec 34 [2] c2 16 [2] d6 0d [2] d9 17 [2] c7 0a [2] c5 0b [2] de 0d [2] c2 0a [2] de 25 }

  condition:
    any of them
}