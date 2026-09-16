rule TTP_XOR_QUAD_CurrentVersionRun_b034 {
  strings:
    $key_b034 = { e3 5b [2] c7 55 [2] ec 79 [2] c2 5b [2] d6 40 [2] d9 5a [2] c7 47 [2] c5 46 [2] de 40 [2] c2 47 [2] de 68 }

  condition:
    any of them
}