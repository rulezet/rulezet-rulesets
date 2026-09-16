rule TTP_XOR_QUAD_CurrentVersionRun_a038 {
  strings:
    $key_a038 = { f3 57 [2] d7 59 [2] fc 75 [2] d2 57 [2] c6 4c [2] c9 56 [2] d7 4b [2] d5 4a [2] ce 4c [2] d2 4b [2] ce 64 }

  condition:
    any of them
}