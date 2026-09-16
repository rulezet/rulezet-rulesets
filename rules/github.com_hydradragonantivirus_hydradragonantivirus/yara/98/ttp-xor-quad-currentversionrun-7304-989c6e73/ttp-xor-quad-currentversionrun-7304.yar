rule TTP_XOR_QUAD_CurrentVersionRun_7304 {
  strings:
    $key_7304 = { 20 6b [2] 04 65 [2] 2f 49 [2] 01 6b [2] 15 70 [2] 1a 6a [2] 04 77 [2] 06 76 [2] 1d 70 [2] 01 77 [2] 1d 58 }

  condition:
    any of them
}