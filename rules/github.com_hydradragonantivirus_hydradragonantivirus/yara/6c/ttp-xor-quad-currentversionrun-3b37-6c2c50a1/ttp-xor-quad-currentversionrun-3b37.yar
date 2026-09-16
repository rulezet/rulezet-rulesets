rule TTP_XOR_QUAD_CurrentVersionRun_3b37 {
  strings:
    $key_3b37 = { 68 58 [2] 4c 56 [2] 67 7a [2] 49 58 [2] 5d 43 [2] 52 59 [2] 4c 44 [2] 4e 45 [2] 55 43 [2] 49 44 [2] 55 6b }

  condition:
    any of them
}