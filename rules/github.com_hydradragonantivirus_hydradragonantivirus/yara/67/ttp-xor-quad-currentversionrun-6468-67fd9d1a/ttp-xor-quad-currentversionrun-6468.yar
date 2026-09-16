rule TTP_XOR_QUAD_CurrentVersionRun_6468 {
  strings:
    $key_6468 = { 37 07 [2] 13 09 [2] 38 25 [2] 16 07 [2] 02 1c [2] 0d 06 [2] 13 1b [2] 11 1a [2] 0a 1c [2] 16 1b [2] 0a 34 }

  condition:
    any of them
}