rule TTP_XOR_QUAD_CurrentVersionRun_030b {
  strings:
    $key_030b = { 50 64 [2] 74 6a [2] 5f 46 [2] 71 64 [2] 65 7f [2] 6a 65 [2] 74 78 [2] 76 79 [2] 6d 7f [2] 71 78 [2] 6d 57 }

  condition:
    any of them
}