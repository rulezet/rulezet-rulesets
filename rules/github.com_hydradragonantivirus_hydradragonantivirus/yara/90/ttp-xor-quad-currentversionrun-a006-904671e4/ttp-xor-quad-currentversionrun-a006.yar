rule TTP_XOR_QUAD_CurrentVersionRun_a006 {
  strings:
    $key_a006 = { f3 69 [2] d7 67 [2] fc 4b [2] d2 69 [2] c6 72 [2] c9 68 [2] d7 75 [2] d5 74 [2] ce 72 [2] d2 75 [2] ce 5a }

  condition:
    any of them
}