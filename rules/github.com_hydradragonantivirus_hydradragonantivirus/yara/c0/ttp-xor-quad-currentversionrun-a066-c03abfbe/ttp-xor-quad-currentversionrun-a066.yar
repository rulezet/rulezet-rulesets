rule TTP_XOR_QUAD_CurrentVersionRun_a066 {
  strings:
    $key_a066 = { f3 09 [2] d7 07 [2] fc 2b [2] d2 09 [2] c6 12 [2] c9 08 [2] d7 15 [2] d5 14 [2] ce 12 [2] d2 15 [2] ce 3a }

  condition:
    any of them
}