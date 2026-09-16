rule TTP_XOR_QUAD_CurrentVersionRun_2f37 {
  strings:
    $key_2f37 = { 7c 58 [2] 58 56 [2] 73 7a [2] 5d 58 [2] 49 43 [2] 46 59 [2] 58 44 [2] 5a 45 [2] 41 43 [2] 5d 44 [2] 41 6b }

  condition:
    any of them
}