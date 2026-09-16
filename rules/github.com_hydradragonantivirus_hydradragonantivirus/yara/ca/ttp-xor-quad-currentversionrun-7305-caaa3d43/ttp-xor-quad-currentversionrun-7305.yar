rule TTP_XOR_QUAD_CurrentVersionRun_7305 {
  strings:
    $key_7305 = { 20 6a [2] 04 64 [2] 2f 48 [2] 01 6a [2] 15 71 [2] 1a 6b [2] 04 76 [2] 06 77 [2] 1d 71 [2] 01 76 [2] 1d 59 }

  condition:
    any of them
}