rule TTP_XOR_QUAD_CurrentVersionRun_7422 {
  strings:
    $key_7422 = { 27 4d [2] 03 43 [2] 28 6f [2] 06 4d [2] 12 56 [2] 1d 4c [2] 03 51 [2] 01 50 [2] 1a 56 [2] 06 51 [2] 1a 7e }

  condition:
    any of them
}