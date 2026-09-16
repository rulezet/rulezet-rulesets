rule TTP_XOR_QUAD_CurrentVersionRun_734b {
  strings:
    $key_734b = { 20 24 [2] 04 2a [2] 2f 06 [2] 01 24 [2] 15 3f [2] 1a 25 [2] 04 38 [2] 06 39 [2] 1d 3f [2] 01 38 [2] 1d 17 }

  condition:
    any of them
}