rule TTP_XOR_QUAD_CurrentVersionRun_a027 {
  strings:
    $key_a027 = { f3 48 [2] d7 46 [2] fc 6a [2] d2 48 [2] c6 53 [2] c9 49 [2] d7 54 [2] d5 55 [2] ce 53 [2] d2 54 [2] ce 7b }

  condition:
    any of them
}