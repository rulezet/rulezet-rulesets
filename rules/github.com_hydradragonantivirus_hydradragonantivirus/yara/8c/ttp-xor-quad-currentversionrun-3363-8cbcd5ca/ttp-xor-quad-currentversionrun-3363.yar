rule TTP_XOR_QUAD_CurrentVersionRun_3363 {
  strings:
    $key_3363 = { 60 0c [2] 44 02 [2] 6f 2e [2] 41 0c [2] 55 17 [2] 5a 0d [2] 44 10 [2] 46 11 [2] 5d 17 [2] 41 10 [2] 5d 3f }

  condition:
    any of them
}