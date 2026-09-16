rule TTP_XOR_QUAD_CurrentVersionRun_481b {
  strings:
    $key_481b = { 1b 74 [2] 3f 7a [2] 14 56 [2] 3a 74 [2] 2e 6f [2] 21 75 [2] 3f 68 [2] 3d 69 [2] 26 6f [2] 3a 68 [2] 26 47 }

  condition:
    any of them
}