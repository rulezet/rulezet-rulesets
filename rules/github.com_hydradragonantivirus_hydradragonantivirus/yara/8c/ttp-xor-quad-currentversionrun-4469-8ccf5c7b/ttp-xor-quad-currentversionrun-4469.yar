rule TTP_XOR_QUAD_CurrentVersionRun_4469 {
  strings:
    $key_4469 = { 17 06 [2] 33 08 [2] 18 24 [2] 36 06 [2] 22 1d [2] 2d 07 [2] 33 1a [2] 31 1b [2] 2a 1d [2] 36 1a [2] 2a 35 }

  condition:
    any of them
}