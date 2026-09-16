rule TTP_XOR_QUAD_CurrentVersionRun_6a45 {
  strings:
    $key_6a45 = { 39 2a [2] 1d 24 [2] 36 08 [2] 18 2a [2] 0c 31 [2] 03 2b [2] 1d 36 [2] 1f 37 [2] 04 31 [2] 18 36 [2] 04 19 }

  condition:
    any of them
}