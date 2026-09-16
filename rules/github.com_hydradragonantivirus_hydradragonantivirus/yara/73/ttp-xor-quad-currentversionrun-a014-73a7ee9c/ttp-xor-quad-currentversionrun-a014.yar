rule TTP_XOR_QUAD_CurrentVersionRun_a014 {
  strings:
    $key_a014 = { f3 7b [2] d7 75 [2] fc 59 [2] d2 7b [2] c6 60 [2] c9 7a [2] d7 67 [2] d5 66 [2] ce 60 [2] d2 67 [2] ce 48 }

  condition:
    any of them
}