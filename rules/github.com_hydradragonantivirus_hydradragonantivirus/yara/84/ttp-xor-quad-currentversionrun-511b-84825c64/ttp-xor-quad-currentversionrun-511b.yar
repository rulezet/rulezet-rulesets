rule TTP_XOR_QUAD_CurrentVersionRun_511b {
  strings:
    $key_511b = { 02 74 [2] 26 7a [2] 0d 56 [2] 23 74 [2] 37 6f [2] 38 75 [2] 26 68 [2] 24 69 [2] 3f 6f [2] 23 68 [2] 3f 47 }

  condition:
    any of them
}