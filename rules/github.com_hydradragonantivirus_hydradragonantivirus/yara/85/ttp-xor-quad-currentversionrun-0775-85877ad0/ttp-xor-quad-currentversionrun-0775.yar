rule TTP_XOR_QUAD_CurrentVersionRun_0775 {
  strings:
    $key_0775 = { 54 1a [2] 70 14 [2] 5b 38 [2] 75 1a [2] 61 01 [2] 6e 1b [2] 70 06 [2] 72 07 [2] 69 01 [2] 75 06 [2] 69 29 }

  condition:
    any of them
}