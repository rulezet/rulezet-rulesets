rule TTP_XOR_QUAD_CurrentVersionRun_5168 {
  strings:
    $key_5168 = { 02 07 [2] 26 09 [2] 0d 25 [2] 23 07 [2] 37 1c [2] 38 06 [2] 26 1b [2] 24 1a [2] 3f 1c [2] 23 1b [2] 3f 34 }

  condition:
    any of them
}