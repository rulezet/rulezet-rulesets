rule TTP_XOR_QUAD_CurrentVersionRun_5642 {
  strings:
    $key_5642 = { 05 2d [2] 21 23 [2] 0a 0f [2] 24 2d [2] 30 36 [2] 3f 2c [2] 21 31 [2] 23 30 [2] 38 36 [2] 24 31 [2] 38 1e }

  condition:
    any of them
}