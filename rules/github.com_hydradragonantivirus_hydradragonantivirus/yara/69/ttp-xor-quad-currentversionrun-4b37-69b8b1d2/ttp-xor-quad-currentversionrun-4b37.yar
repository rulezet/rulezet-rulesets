rule TTP_XOR_QUAD_CurrentVersionRun_4b37 {
  strings:
    $key_4b37 = { 18 58 [2] 3c 56 [2] 17 7a [2] 39 58 [2] 2d 43 [2] 22 59 [2] 3c 44 [2] 3e 45 [2] 25 43 [2] 39 44 [2] 25 6b }

  condition:
    any of them
}