rule TTP_XOR_QUAD_CurrentVersionRun_765a {
  strings:
    $key_765a = { 25 35 [2] 01 3b [2] 2a 17 [2] 04 35 [2] 10 2e [2] 1f 34 [2] 01 29 [2] 03 28 [2] 18 2e [2] 04 29 [2] 18 06 }

  condition:
    any of them
}