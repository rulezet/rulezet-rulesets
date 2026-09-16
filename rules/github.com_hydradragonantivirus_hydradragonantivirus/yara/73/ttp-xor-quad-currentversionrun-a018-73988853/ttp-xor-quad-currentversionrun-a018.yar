rule TTP_XOR_QUAD_CurrentVersionRun_a018 {
  strings:
    $key_a018 = { f3 77 [2] d7 79 [2] fc 55 [2] d2 77 [2] c6 6c [2] c9 76 [2] d7 6b [2] d5 6a [2] ce 6c [2] d2 6b [2] ce 44 }

  condition:
    any of them
}