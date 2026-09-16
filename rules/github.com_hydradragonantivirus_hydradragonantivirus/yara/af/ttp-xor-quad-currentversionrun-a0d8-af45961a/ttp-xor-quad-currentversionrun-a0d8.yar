rule TTP_XOR_QUAD_CurrentVersionRun_a0d8 {
  strings:
    $key_a0d8 = { f3 b7 [2] d7 b9 [2] fc 95 [2] d2 b7 [2] c6 ac [2] c9 b6 [2] d7 ab [2] d5 aa [2] ce ac [2] d2 ab [2] ce 84 }

  condition:
    any of them
}