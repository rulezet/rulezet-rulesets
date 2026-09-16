rule TTP_XOR_QUAD_CurrentVersionRun_7642 {
  strings:
    $key_7642 = { 25 2d [2] 01 23 [2] 2a 0f [2] 04 2d [2] 10 36 [2] 1f 2c [2] 01 31 [2] 03 30 [2] 18 36 [2] 04 31 [2] 18 1e }

  condition:
    any of them
}