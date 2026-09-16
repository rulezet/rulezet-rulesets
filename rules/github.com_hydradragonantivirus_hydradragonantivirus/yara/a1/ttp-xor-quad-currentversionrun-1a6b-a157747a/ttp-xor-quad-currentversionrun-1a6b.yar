rule TTP_XOR_QUAD_CurrentVersionRun_1a6b {
  strings:
    $key_1a6b = { 49 04 [2] 6d 0a [2] 46 26 [2] 68 04 [2] 7c 1f [2] 73 05 [2] 6d 18 [2] 6f 19 [2] 74 1f [2] 68 18 [2] 74 37 }

  condition:
    any of them
}