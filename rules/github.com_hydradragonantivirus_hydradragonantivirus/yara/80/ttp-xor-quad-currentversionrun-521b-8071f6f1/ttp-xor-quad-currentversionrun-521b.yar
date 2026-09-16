rule TTP_XOR_QUAD_CurrentVersionRun_521b {
  strings:
    $key_521b = { 01 74 [2] 25 7a [2] 0e 56 [2] 20 74 [2] 34 6f [2] 3b 75 [2] 25 68 [2] 27 69 [2] 3c 6f [2] 20 68 [2] 3c 47 }

  condition:
    any of them
}