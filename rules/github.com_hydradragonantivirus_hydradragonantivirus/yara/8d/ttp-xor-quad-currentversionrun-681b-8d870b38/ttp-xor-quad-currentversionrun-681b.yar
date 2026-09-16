rule TTP_XOR_QUAD_CurrentVersionRun_681b {
  strings:
    $key_681b = { 3b 74 [2] 1f 7a [2] 34 56 [2] 1a 74 [2] 0e 6f [2] 01 75 [2] 1f 68 [2] 1d 69 [2] 06 6f [2] 1a 68 [2] 06 47 }

  condition:
    any of them
}