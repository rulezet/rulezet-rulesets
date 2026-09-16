rule TTP_XOR_QUAD_CurrentVersionRun_4672 {
  strings:
    $key_4672 = { 15 1d [2] 31 13 [2] 1a 3f [2] 34 1d [2] 20 06 [2] 2f 1c [2] 31 01 [2] 33 00 [2] 28 06 [2] 34 01 [2] 28 2e }

  condition:
    any of them
}