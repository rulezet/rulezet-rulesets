rule TTP_XOR_QUAD_CurrentVersionRun_2177 {
  strings:
    $key_2177 = { 72 18 [2] 56 16 [2] 7d 3a [2] 53 18 [2] 47 03 [2] 48 19 [2] 56 04 [2] 54 05 [2] 4f 03 [2] 53 04 [2] 4f 2b }

  condition:
    any of them
}