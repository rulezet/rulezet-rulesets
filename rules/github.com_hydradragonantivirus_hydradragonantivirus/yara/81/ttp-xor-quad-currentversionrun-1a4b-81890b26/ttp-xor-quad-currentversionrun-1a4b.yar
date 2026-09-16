rule TTP_XOR_QUAD_CurrentVersionRun_1a4b {
  strings:
    $key_1a4b = { 49 24 [2] 6d 2a [2] 46 06 [2] 68 24 [2] 7c 3f [2] 73 25 [2] 6d 38 [2] 6f 39 [2] 74 3f [2] 68 38 [2] 74 17 }

  condition:
    any of them
}