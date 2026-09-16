rule TTP_XOR_QUAD_CurrentVersionRun_60e2 {
  strings:
    $key_60e2 = { 33 8d [2] 17 83 [2] 3c af [2] 12 8d [2] 06 96 [2] 09 8c [2] 17 91 [2] 15 90 [2] 0e 96 [2] 12 91 [2] 0e be }

  condition:
    any of them
}