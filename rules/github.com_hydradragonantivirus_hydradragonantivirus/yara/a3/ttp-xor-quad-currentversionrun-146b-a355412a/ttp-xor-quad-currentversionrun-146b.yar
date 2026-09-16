rule TTP_XOR_QUAD_CurrentVersionRun_146b {
  strings:
    $key_146b = { 47 04 [2] 63 0a [2] 48 26 [2] 66 04 [2] 72 1f [2] 7d 05 [2] 63 18 [2] 61 19 [2] 7a 1f [2] 66 18 [2] 7a 37 }

  condition:
    any of them
}