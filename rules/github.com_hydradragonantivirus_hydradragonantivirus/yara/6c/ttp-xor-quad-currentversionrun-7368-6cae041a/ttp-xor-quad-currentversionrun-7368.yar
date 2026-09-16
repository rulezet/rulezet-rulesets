rule TTP_XOR_QUAD_CurrentVersionRun_7368 {
  strings:
    $key_7368 = { 20 07 [2] 04 09 [2] 2f 25 [2] 01 07 [2] 15 1c [2] 1a 06 [2] 04 1b [2] 06 1a [2] 1d 1c [2] 01 1b [2] 1d 34 }

  condition:
    any of them
}