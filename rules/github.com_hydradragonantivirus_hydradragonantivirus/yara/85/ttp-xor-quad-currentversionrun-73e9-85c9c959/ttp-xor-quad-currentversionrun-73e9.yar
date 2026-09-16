rule TTP_XOR_QUAD_CurrentVersionRun_73e9 {
  strings:
    $key_73e9 = { 20 86 [2] 04 88 [2] 2f a4 [2] 01 86 [2] 15 9d [2] 1a 87 [2] 04 9a [2] 06 9b [2] 1d 9d [2] 01 9a [2] 1d b5 }

  condition:
    any of them
}