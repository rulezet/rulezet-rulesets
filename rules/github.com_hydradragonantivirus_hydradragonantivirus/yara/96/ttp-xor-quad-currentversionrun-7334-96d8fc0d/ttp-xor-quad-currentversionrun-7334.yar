rule TTP_XOR_QUAD_CurrentVersionRun_7334 {
  strings:
    $key_7334 = { 20 5b [2] 04 55 [2] 2f 79 [2] 01 5b [2] 15 40 [2] 1a 5a [2] 04 47 [2] 06 46 [2] 1d 40 [2] 01 47 [2] 1d 68 }

  condition:
    any of them
}