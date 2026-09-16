rule TTP_XOR_QUAD_CurrentVersionRun_7e37 {
  strings:
    $key_7e37 = { 2d 58 [2] 09 56 [2] 22 7a [2] 0c 58 [2] 18 43 [2] 17 59 [2] 09 44 [2] 0b 45 [2] 10 43 [2] 0c 44 [2] 10 6b }

  condition:
    any of them
}