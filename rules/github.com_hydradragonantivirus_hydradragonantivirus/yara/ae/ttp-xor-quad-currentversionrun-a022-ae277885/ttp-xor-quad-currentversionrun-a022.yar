rule TTP_XOR_QUAD_CurrentVersionRun_a022 {
  strings:
    $key_a022 = { f3 4d [2] d7 43 [2] fc 6f [2] d2 4d [2] c6 56 [2] c9 4c [2] d7 51 [2] d5 50 [2] ce 56 [2] d2 51 [2] ce 7e }

  condition:
    any of them
}