rule TTP_XOR_QUAD_CurrentVersionRun_526b {
  strings:
    $key_526b = { 01 04 [2] 25 0a [2] 0e 26 [2] 20 04 [2] 34 1f [2] 3b 05 [2] 25 18 [2] 27 19 [2] 3c 1f [2] 20 18 [2] 3c 37 }

  condition:
    any of them
}