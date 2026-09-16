rule TTP_XOR_QUAD_CurrentVersionRun_3463 {
  strings:
    $key_3463 = { 67 0c [2] 43 02 [2] 68 2e [2] 46 0c [2] 52 17 [2] 5d 0d [2] 43 10 [2] 41 11 [2] 5a 17 [2] 46 10 [2] 5a 3f }

  condition:
    any of them
}