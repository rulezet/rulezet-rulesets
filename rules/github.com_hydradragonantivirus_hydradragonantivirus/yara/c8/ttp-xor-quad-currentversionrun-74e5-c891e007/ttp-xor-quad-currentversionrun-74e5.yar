rule TTP_XOR_QUAD_CurrentVersionRun_74e5 {
  strings:
    $key_74e5 = { 27 8a [2] 03 84 [2] 28 a8 [2] 06 8a [2] 12 91 [2] 1d 8b [2] 03 96 [2] 01 97 [2] 1a 91 [2] 06 96 [2] 1a b9 }

  condition:
    any of them
}