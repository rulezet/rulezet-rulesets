rule TTP_XOR_QUAD_CurrentVersionRun_2168 {
  strings:
    $key_2168 = { 72 07 [2] 56 09 [2] 7d 25 [2] 53 07 [2] 47 1c [2] 48 06 [2] 56 1b [2] 54 1a [2] 4f 1c [2] 53 1b [2] 4f 34 }

  condition:
    any of them
}