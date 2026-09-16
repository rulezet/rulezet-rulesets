rule TTP_XOR_QUAD_CurrentVersionRun_a029 {
  strings:
    $key_a029 = { f3 46 [2] d7 48 [2] fc 64 [2] d2 46 [2] c6 5d [2] c9 47 [2] d7 5a [2] d5 5b [2] ce 5d [2] d2 5a [2] ce 75 }

  condition:
    any of them
}