rule TTP_XOR_QUAD_CurrentVersionRun_a060 {
  strings:
    $key_a060 = { f3 0f [2] d7 01 [2] fc 2d [2] d2 0f [2] c6 14 [2] c9 0e [2] d7 13 [2] d5 12 [2] ce 14 [2] d2 13 [2] ce 3c }

  condition:
    any of them
}