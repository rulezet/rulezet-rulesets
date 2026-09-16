rule TTP_XOR_QUAD_CurrentVersionRun_a005 {
  strings:
    $key_a005 = { f3 6a [2] d7 64 [2] fc 48 [2] d2 6a [2] c6 71 [2] c9 6b [2] d7 76 [2] d5 77 [2] ce 71 [2] d2 76 [2] ce 59 }

  condition:
    any of them
}