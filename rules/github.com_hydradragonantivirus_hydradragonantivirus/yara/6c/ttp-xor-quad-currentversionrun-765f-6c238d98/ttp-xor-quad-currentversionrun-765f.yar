rule TTP_XOR_QUAD_CurrentVersionRun_765f {
  strings:
    $key_765f = { 25 30 [2] 01 3e [2] 2a 12 [2] 04 30 [2] 10 2b [2] 1f 31 [2] 01 2c [2] 03 2d [2] 18 2b [2] 04 2c [2] 18 03 }

  condition:
    any of them
}