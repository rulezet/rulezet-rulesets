rule TTP_XOR_QUAD_CurrentVersionRun_a035 {
  strings:
    $key_a035 = { f3 5a [2] d7 54 [2] fc 78 [2] d2 5a [2] c6 41 [2] c9 5b [2] d7 46 [2] d5 47 [2] ce 41 [2] d2 46 [2] ce 69 }

  condition:
    any of them
}