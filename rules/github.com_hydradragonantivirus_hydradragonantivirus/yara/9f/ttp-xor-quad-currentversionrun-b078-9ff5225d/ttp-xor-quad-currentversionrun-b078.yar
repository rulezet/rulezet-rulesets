rule TTP_XOR_QUAD_CurrentVersionRun_b078 {
  strings:
    $key_b078 = { e3 17 [2] c7 19 [2] ec 35 [2] c2 17 [2] d6 0c [2] d9 16 [2] c7 0b [2] c5 0a [2] de 0c [2] c2 0b [2] de 24 }

  condition:
    any of them
}