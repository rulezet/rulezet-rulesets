rule TTP_XOR_QUAD_CurrentVersionRun_765e {
  strings:
    $key_765e = { 25 31 [2] 01 3f [2] 2a 13 [2] 04 31 [2] 10 2a [2] 1f 30 [2] 01 2d [2] 03 2c [2] 18 2a [2] 04 2d [2] 18 02 }

  condition:
    any of them
}