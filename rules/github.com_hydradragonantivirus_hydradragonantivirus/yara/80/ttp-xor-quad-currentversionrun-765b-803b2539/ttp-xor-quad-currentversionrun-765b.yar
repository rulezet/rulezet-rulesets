rule TTP_XOR_QUAD_CurrentVersionRun_765b {
  strings:
    $key_765b = { 25 34 [2] 01 3a [2] 2a 16 [2] 04 34 [2] 10 2f [2] 1f 35 [2] 01 28 [2] 03 29 [2] 18 2f [2] 04 28 [2] 18 07 }

  condition:
    any of them
}