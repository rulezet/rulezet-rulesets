rule TTP_XOR_QUAD_CurrentVersionRun_0875 {
  strings:
    $key_0875 = { 5b 1a [2] 7f 14 [2] 54 38 [2] 7a 1a [2] 6e 01 [2] 61 1b [2] 7f 06 [2] 7d 07 [2] 66 01 [2] 7a 06 [2] 66 29 }

  condition:
    any of them
}