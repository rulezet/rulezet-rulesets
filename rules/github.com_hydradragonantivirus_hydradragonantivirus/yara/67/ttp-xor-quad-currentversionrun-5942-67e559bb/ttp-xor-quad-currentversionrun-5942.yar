rule TTP_XOR_QUAD_CurrentVersionRun_5942 {
  strings:
    $key_5942 = { 0a 2d [2] 2e 23 [2] 05 0f [2] 2b 2d [2] 3f 36 [2] 30 2c [2] 2e 31 [2] 2c 30 [2] 37 36 [2] 2b 31 [2] 37 1e }

  condition:
    any of them
}