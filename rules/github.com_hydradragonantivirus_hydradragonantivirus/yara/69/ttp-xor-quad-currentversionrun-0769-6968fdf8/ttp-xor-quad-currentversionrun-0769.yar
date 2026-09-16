rule TTP_XOR_QUAD_CurrentVersionRun_0769 {
  strings:
    $key_0769 = { 54 06 [2] 70 08 [2] 5b 24 [2] 75 06 [2] 61 1d [2] 6e 07 [2] 70 1a [2] 72 1b [2] 69 1d [2] 75 1a [2] 69 35 }

  condition:
    any of them
}