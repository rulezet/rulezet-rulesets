rule TTP_XOR_QUAD_CurrentVersionRun_6a69 {
  strings:
    $key_6a69 = { 39 06 [2] 1d 08 [2] 36 24 [2] 18 06 [2] 0c 1d [2] 03 07 [2] 1d 1a [2] 1f 1b [2] 04 1d [2] 18 1a [2] 04 35 }

  condition:
    any of them
}