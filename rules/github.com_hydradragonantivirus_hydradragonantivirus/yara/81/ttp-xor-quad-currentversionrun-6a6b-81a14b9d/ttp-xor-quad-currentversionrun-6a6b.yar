rule TTP_XOR_QUAD_CurrentVersionRun_6a6b {
  strings:
    $key_6a6b = { 39 04 [2] 1d 0a [2] 36 26 [2] 18 04 [2] 0c 1f [2] 03 05 [2] 1d 18 [2] 1f 19 [2] 04 1f [2] 18 18 [2] 04 37 }

  condition:
    any of them
}