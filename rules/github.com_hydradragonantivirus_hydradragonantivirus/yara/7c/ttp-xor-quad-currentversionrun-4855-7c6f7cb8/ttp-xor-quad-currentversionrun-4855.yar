rule TTP_XOR_QUAD_CurrentVersionRun_4855 {
  strings:
    $key_4855 = { 1b 3a [2] 3f 34 [2] 14 18 [2] 3a 3a [2] 2e 21 [2] 21 3b [2] 3f 26 [2] 3d 27 [2] 26 21 [2] 3a 26 [2] 26 09 }

  condition:
    any of them
}