rule TTP_XOR_QUAD_CurrentVersionRun_6a65 {
  strings:
    $key_6a65 = { 39 0a [2] 1d 04 [2] 36 28 [2] 18 0a [2] 0c 11 [2] 03 0b [2] 1d 16 [2] 1f 17 [2] 04 11 [2] 18 16 [2] 04 39 }

  condition:
    any of them
}