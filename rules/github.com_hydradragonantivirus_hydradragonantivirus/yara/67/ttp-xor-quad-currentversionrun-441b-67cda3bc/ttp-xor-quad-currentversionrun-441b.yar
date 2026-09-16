rule TTP_XOR_QUAD_CurrentVersionRun_441b {
  strings:
    $key_441b = { 17 74 [2] 33 7a [2] 18 56 [2] 36 74 [2] 22 6f [2] 2d 75 [2] 33 68 [2] 31 69 [2] 2a 6f [2] 36 68 [2] 2a 47 }

  condition:
    any of them
}