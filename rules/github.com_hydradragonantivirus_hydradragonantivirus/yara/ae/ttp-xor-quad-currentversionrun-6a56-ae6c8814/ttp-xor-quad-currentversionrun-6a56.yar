rule TTP_XOR_QUAD_CurrentVersionRun_6a56 {
  strings:
    $key_6a56 = { 39 39 [2] 1d 37 [2] 36 1b [2] 18 39 [2] 0c 22 [2] 03 38 [2] 1d 25 [2] 1f 24 [2] 04 22 [2] 18 25 [2] 04 0a }

  condition:
    any of them
}