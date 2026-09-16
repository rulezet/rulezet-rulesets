rule TTP_XOR_QUAD_CurrentVersionRun_6377 {
  strings:
    $key_6377 = { 30 18 [2] 14 16 [2] 3f 3a [2] 11 18 [2] 05 03 [2] 0a 19 [2] 14 04 [2] 16 05 [2] 0d 03 [2] 11 04 [2] 0d 2b }

  condition:
    any of them
}