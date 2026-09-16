rule TTP_XOR_QUAD_CurrentVersionRun_6a44 {
  strings:
    $key_6a44 = { 39 2b [2] 1d 25 [2] 36 09 [2] 18 2b [2] 0c 30 [2] 03 2a [2] 1d 37 [2] 1f 36 [2] 04 30 [2] 18 37 [2] 04 18 }

  condition:
    any of them
}