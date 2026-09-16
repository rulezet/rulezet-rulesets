rule TTP_XOR_QUAD_CurrentVersionRun_016b {
  strings:
    $key_016b = { 52 04 [2] 76 0a [2] 5d 26 [2] 73 04 [2] 67 1f [2] 68 05 [2] 76 18 [2] 74 19 [2] 6f 1f [2] 73 18 [2] 6f 37 }

  condition:
    any of them
}