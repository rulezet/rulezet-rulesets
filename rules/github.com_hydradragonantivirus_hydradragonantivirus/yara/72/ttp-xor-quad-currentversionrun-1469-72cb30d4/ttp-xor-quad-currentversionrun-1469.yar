rule TTP_XOR_QUAD_CurrentVersionRun_1469 {
  strings:
    $key_1469 = { 47 06 [2] 63 08 [2] 48 24 [2] 66 06 [2] 72 1d [2] 7d 07 [2] 63 1a [2] 61 1b [2] 7a 1d [2] 66 1a [2] 7a 35 }

  condition:
    any of them
}