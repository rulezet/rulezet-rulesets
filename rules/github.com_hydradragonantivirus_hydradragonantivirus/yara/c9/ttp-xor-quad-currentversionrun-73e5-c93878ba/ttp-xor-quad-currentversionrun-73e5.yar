rule TTP_XOR_QUAD_CurrentVersionRun_73e5 {
  strings:
    $key_73e5 = { 20 8a [2] 04 84 [2] 2f a8 [2] 01 8a [2] 15 91 [2] 1a 8b [2] 04 96 [2] 06 97 [2] 1d 91 [2] 01 96 [2] 1d b9 }

  condition:
    any of them
}