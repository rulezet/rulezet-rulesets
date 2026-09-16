rule TTP_XOR_QUAD_CurrentVersionRun_2157 {
  strings:
    $key_2157 = { 72 38 [2] 56 36 [2] 7d 1a [2] 53 38 [2] 47 23 [2] 48 39 [2] 56 24 [2] 54 25 [2] 4f 23 [2] 53 24 [2] 4f 0b }

  condition:
    any of them
}