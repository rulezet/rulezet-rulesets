rule TTP_XOR_QUAD_CurrentVersionRun_a078 {
  strings:
    $key_a078 = { f3 17 [2] d7 19 [2] fc 35 [2] d2 17 [2] c6 0c [2] c9 16 [2] d7 0b [2] d5 0a [2] ce 0c [2] d2 0b [2] ce 24 }

  condition:
    any of them
}