rule TTP_XOR_QUAD_CurrentVersionRun_3368 {
  strings:
    $key_3368 = { 60 07 [2] 44 09 [2] 6f 25 [2] 41 07 [2] 55 1c [2] 5a 06 [2] 44 1b [2] 46 1a [2] 5d 1c [2] 41 1b [2] 5d 34 }

  condition:
    any of them
}