rule TTP_XOR_QUAD_CurrentVersionRun_6f09 {
  strings:
    $key_6f09 = { 3c 66 [2] 18 68 [2] 33 44 [2] 1d 66 [2] 09 7d [2] 06 67 [2] 18 7a [2] 1a 7b [2] 01 7d [2] 1d 7a [2] 01 55 }

  condition:
    any of them
}